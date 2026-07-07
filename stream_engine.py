"""
FRAUD-X  ·  Async Stream Processing Engine
==========================================
Kafka-compatible streaming interface with asyncio queue fallback.

Design
------
  If kafka-python is installed, messages are consumed from a Kafka topic
  and scored in real-time. Otherwise an in-process asyncio.Queue mimics
  the same interface so the rest of the system works identically.

  Each message in the stream is a JSON-serialisable dict matching the
  TransactionEvent schema expected by transaction_engine.

Pipeline
--------
  Producer → Stream → Scorer → Risk Engine → Feedback / Alert

Usage
-----
  stream = StreamEngine()
  await stream.start()                   # start consumer loop
  await stream.publish(event_dict)       # push from tests / API
  await stream.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("fraudx.stream")

# ── Kafka availability ──────────────────────────────────────────────────────
try:
    from kafka import KafkaProducer, KafkaConsumer
    from kafka.errors import KafkaError
    _KAFKA = True
    logger.info("[STREAM] kafka-python available")
except ImportError:
    _KAFKA = False
    logger.info("[STREAM] kafka-python not found — using asyncio.Queue fallback")

KAFKA_TOPIC   = "fraudx.transactions"
KAFKA_BROKERS = ["localhost:9092"]
QUEUE_MAX     = 10_000    # asyncio fallback max depth
BATCH_SIZE    = 50        # max events scored per loop iteration
BATCH_TIMEOUT = 0.1       # seconds to wait for a full batch


# ═════════════════════════════════════════════════════════════════════════════
# Data structures
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class StreamEvent:
    transaction_id: str
    user_id:        str
    amount:         float
    merchant:       str        = ""
    card_last4:     str        = ""
    ip_address:     str        = ""
    latitude:       float      = 0.0
    longitude:      float      = 0.0
    currency:       str        = "USD"
    extra:          Dict       = field(default_factory=dict)
    ts:             float      = field(default_factory=time.time)


@dataclass
class StreamResult:
    transaction_id: str
    user_id:        str
    final_score:    int
    band:           str
    action:         str
    confidence:     str
    reasons:        List[str]
    elapsed_ms:     float
    ts:             float = field(default_factory=time.time)


# ═════════════════════════════════════════════════════════════════════════════
# StreamEngine
# ═════════════════════════════════════════════════════════════════════════════

class StreamEngine:
    """
    Async streaming fraud detection pipeline.

    Callbacks
    ---------
      on_result(StreamResult)  — called after each scored event
      on_alert(StreamResult)   — called when band is high or critical
    """

    def __init__(
        self,
        on_result: Optional[Callable[[StreamResult], Coroutine]] = None,
        on_alert:  Optional[Callable[[StreamResult], Coroutine]] = None,
    ) -> None:
        self._on_result = on_result
        self._on_alert  = on_alert
        self._queue:  asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
        self._running = False
        self._task:   Optional[asyncio.Task] = None
        self._processed = 0
        self._alerts    = 0
        self._recent_results: deque = deque(maxlen=500)

        # Kafka producer (lazy-init)
        self._producer = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        if _KAFKA:
            self._task = asyncio.create_task(self._kafka_consumer_loop())
        else:
            self._task = asyncio.create_task(self._queue_consumer_loop())
        logger.info("[STREAM] Started (%s backend)", "kafka" if _KAFKA else "asyncio-queue")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._producer:
            try:
                self._producer.close()
            except Exception:
                pass
        logger.info("[STREAM] Stopped. Processed=%d Alerts=%d", self._processed, self._alerts)

    # ── Publishing ─────────────────────────────────────────────────────────────

    async def publish(self, event: Dict | StreamEvent) -> None:
        """
        Push an event into the stream.
        Works with both Kafka and asyncio-queue backends.
        """
        if isinstance(event, StreamEvent):
            payload = asdict(event)
        else:
            payload = dict(event)

        if _KAFKA:
            await self._kafka_publish(payload)
        else:
            await self._queue.put(payload)

    async def _kafka_publish(self, payload: Dict) -> None:
        try:
            if self._producer is None:
                loop = asyncio.get_event_loop()
                self._producer = await loop.run_in_executor(
                    None,
                    lambda: KafkaProducer(
                        bootstrap_servers=KAFKA_BROKERS,
                        value_serializer=lambda v: json.dumps(v).encode(),
                        request_timeout_ms=5000,
                    ),
                )
            self._producer.send(KAFKA_TOPIC, payload)
        except Exception as exc:
            logger.warning("[STREAM] Kafka publish failed (%s) — falling back to queue", exc)
            await self._queue.put(payload)

    # ── Consumer loops ─────────────────────────────────────────────────────────

    async def _queue_consumer_loop(self) -> None:
        logger.debug("[STREAM] asyncio queue consumer running")
        while self._running:
            batch: List[Dict] = []
            deadline = time.monotonic() + BATCH_TIMEOUT
            while len(batch) < BATCH_SIZE and time.monotonic() < deadline:
                try:
                    remaining = max(0.0, deadline - time.monotonic())
                    item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    batch.append(item)
                except asyncio.TimeoutError:
                    break
            if batch:
                await self._process_batch(batch)

    async def _kafka_consumer_loop(self) -> None:
        logger.debug("[STREAM] Kafka consumer loop starting")
        loop = asyncio.get_event_loop()
        try:
            consumer: KafkaConsumer = await loop.run_in_executor(
                None,
                lambda: KafkaConsumer(
                    KAFKA_TOPIC,
                    bootstrap_servers=KAFKA_BROKERS,
                    value_deserializer=lambda m: json.loads(m.decode()),
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    group_id="fraudx-scorer",
                    consumer_timeout_ms=100,
                ),
            )
        except Exception as exc:
            logger.warning("[STREAM] Kafka consumer init failed: %s — falling back to queue", exc)
            await self._queue_consumer_loop()
            return

        while self._running:
            try:
                messages = await loop.run_in_executor(
                    None, lambda: list(consumer)
                )
                if messages:
                    batch = [m.value for m in messages[:BATCH_SIZE]]
                    await self._process_batch(batch)
                else:
                    await asyncio.sleep(BATCH_TIMEOUT)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[STREAM] Kafka consumer error: %s", exc)
                await asyncio.sleep(1.0)

        consumer.close()

    # ── Scoring ────────────────────────────────────────────────────────────────

    async def _process_batch(self, batch: List[Dict]) -> None:
        loop = asyncio.get_event_loop()
        for payload in batch:
            t0 = time.monotonic()
            try:
                result = await loop.run_in_executor(None, self._score_one, payload)
                elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
                result.elapsed_ms = elapsed_ms
                self._processed += 1
                self._recent_results.append(result)

                if self._on_result:
                    await self._on_result(result)

                if result.band in ("high", "critical"):
                    self._alerts += 1
                    if self._on_alert:
                        await self._on_alert(result)
                    logger.warning(
                        "[STREAM] ALERT txn=%s score=%d band=%s",
                        result.transaction_id, result.final_score, result.band,
                    )
            except Exception as exc:
                logger.error("[STREAM] Scoring failed for %s: %s",
                             payload.get("transaction_id", "?"), exc)

    def _score_one(self, payload: Dict) -> StreamResult:
        """Synchronous scoring — runs in executor thread."""
        from transaction_engine import transaction_engine, TransactionEvent
        from risk_engine_v2 import risk_engine_v2, RiskSignals

        event = TransactionEvent(
            user_id=str(payload.get("user_id", "")),
            amount=float(payload.get("amount", 0)),
            merchant=str(payload.get("merchant", "")),
            card_last4=str(payload.get("card_last4", "")),
            ip_address=str(payload.get("ip_address", "")),
            latitude=float(payload.get("latitude", 0)),
            longitude=float(payload.get("longitude", 0)),
            currency=str(payload.get("currency", "USD")),
        )

        tx_result  = transaction_engine.analyze(event)
        reasons    = list(tx_result.reasons)

        signals = RiskSignals(
            velocity      = float(tx_result.velocity_score),
            graph         = 0.0,
            device_fp     = 0.0,
            biometrics    = 0.0,
            ensemble_ml   = 0.0,
            autoencoder   = 0.0,
            sequence_lstm = 0.0,
            threat_intel  = 0.0,
        )

        decision = risk_engine_v2.score(signals, reasons=reasons)

        return StreamResult(
            transaction_id = str(payload.get("transaction_id", "")),
            user_id        = str(payload.get("user_id", "")),
            final_score    = decision.final_score,
            band           = decision.band,
            action         = decision.action,
            confidence     = decision.confidence,
            reasons        = decision.reasons,
            elapsed_ms     = 0.0,
        )

    # ── Metrics ────────────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        recent = list(self._recent_results)
        band_counts: Dict[str, int] = {}
        for r in recent:
            band_counts[r.band] = band_counts.get(r.band, 0) + 1

        avg_elapsed = (
            round(sum(r.elapsed_ms for r in recent) / len(recent), 1)
            if recent else 0.0
        )
        return {
            "processed":       self._processed,
            "alerts":          self._alerts,
            "alert_rate":      round(self._alerts / self._processed, 4) if self._processed else 0.0,
            "recent_n":        len(recent),
            "band_counts":     band_counts,
            "avg_elapsed_ms":  avg_elapsed,
            "queue_depth":     self._queue.qsize(),
            "backend":         "kafka" if _KAFKA else "asyncio-queue",
            "running":         self._running,
        }

    @property
    def is_running(self) -> bool:
        return self._running


# ── Singleton ──────────────────────────────────────────────────────────────────
stream_engine = StreamEngine()

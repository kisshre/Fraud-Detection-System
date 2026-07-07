<<<<<<< HEAD
# FRAUD-X — Real-Time Fraud Detection System

A full-stack, AI-powered fraud detection platform built with **FastAPI**, **Gemini AI**, **Machine Learning**, and a **Blockchain-style audit ledger**.

The web dashboard is named **Sentinel** and provides real-time scanning, a live threat feed, and multi-scanner protection across URLs, emails, phone numbers, SMS, files, merchants, social profiles, QR codes, IP addresses, cryptocurrency wallets, and payment gateways.
=======
# FRAUD-X: AI-Powered Online Financial Fraud Detection System

## Overview

FRAUD-X is my final year Computer Science Engineering project. I developed this application to detect fraudulent financial transactions using machine learning algorithms. The system analyzes transaction data, predicts fraud in real time, and provides an easy-to-use dashboard for monitoring and analysis.

The project combines machine learning with a modern web interface and desktop application to provide a complete fraud detection solution.
>>>>>>> 4d0519c343af8d105e1bc4c69f7667c9ef395fc7

---

## Features

<<<<<<< HEAD
| Layer | What it does |
|---|---|
| **Heuristic Engine** | 100+ signals — typosquatting, leet-speak, brand spoofing, entropy |
| **AI Analysis** | Google Flash deep-reasons every scan |
| **ML Model** | Scikit-learn URL classifier, auto-trains on first run |
| **Graph Engine** | NetworkX PageRank + guilt-by-association BFS |
| **Behavioral Engine** | Velocity detection, campaign clustering |
| **Blockchain Ledger** | SHA-256 chained append-only audit log |
| **Payment Gateway Layer** | Real-time fake checkout detection (extension + dashboard) |
| **Auth System** | Email, Mobile OTP, Google OAuth — JWT sessions |
| **Chrome Extension** | Passive background scanning + payment overlay warnings |
| **WebSocket Feed** | Real-time alerts pushed to dashboard instantly |

---

## Requirements

- **Python 3.10 or higher**
- **pip** (comes with Python)
- Internet connection (for Gemini AI calls)
- Google Chrome (for the browser extension — optional)

---

## Installation on a New Computer

### Step 1 — Clone or copy the project folder

Copy the entire `fraud x` folder to the new machine, or extract the zip.

### Step 2 — Open a terminal in the project folder

```
cd "fraud x"
```

### Step 3 — (Recommended) Create a virtual environment

```bash
python -m venv venv
```

Activate it:

- **Windows:**
  ```
  venv\Scripts\activate
  ```
- **Mac / Linux:**
  ```
  source venv/bin/activate
  ```

### Step 4 — Install all dependencies

```bash
pip install -r requirements.txt
```

This installs everything: FastAPI, Uvicorn, scikit-learn, NetworkX, bcrypt, PyJWT, python-dotenv, httpx, and all other packages.

### Step 5 — Configure your API key

Create a file called `.env` in the project root (same folder as `main.py`) with this content:


### Step 6 — Train the ML model (first run only)

```bash
python train_model.py
```

This creates `url_model.pkl`. It only needs to be done once. If you skip this, the server will auto-train on first startup (takes a few seconds).

### Step 7 — Start the server

```bash
uvicorn main:app --reload --port 8000
```

You should see:

```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

### Step 8 — Open the dashboard

Open your browser and go to:

```
http://localhost:8000
```

You will be redirected to the **Sign In** page. Create an account first, then you will be taken to the **Sentinel** dashboard.

---

## First-Time Account Setup

1. Go to `http://localhost:8000/signup`
2. Choose **Email**, **Mobile**, or **Google**
3. Fill in your details and click **Create Account**
4. You will be automatically redirected to the dashboard

> **Mobile OTP in development mode:** The OTP is returned directly in the response and auto-filled in the form — no SMS gateway needed for testing.

---

## Pages & URLs

| URL | Page |
|---|---|
| `http://localhost:8000/` | Sentinel Dashboard (requires login) |
| `http://localhost:8000/login` | Sign In |
| `http://localhost:8000/signup` | Create Account |
| `http://localhost:8000/docs` | Auto-generated API docs (Swagger UI) |
| `http://localhost:8000/redoc` | API docs (ReDoc) |

---

## Scanners

| Scanner | Endpoint | What it detects |
|---|---|---|
| URL / Link | `POST /api/scan/url` | Phishing, typosquatting, malicious redirects |
| Email | `POST /api/scan/email` | Phishing emails, spoofing, credential harvesting |
| Phone | `POST /api/scan/phone` | Scam calls, IRS/HMRC impersonation, wangiri |
| SMS | `POST /api/scan/sms` | Smishing, fake delivery, OTP theft |
| File | `POST /api/scan/file` | Malware, PE executables, macro documents |
| Merchant | `POST /api/scan/merchant` | Fake merchants, impersonation, new accounts |
| Social | `POST /api/scan/social` | Fake profiles, bot accounts |
| QR Code | `POST /api/scan/qr` | Malicious QR destinations |
| IP Address | `POST /api/scan/ip` | Proxy/VPN/Tor IPs, malicious hosts |
| Crypto | `POST /api/scan/crypto` | Scam wallet addresses |
| Bulk URL | `POST /api/scan/bulk` | Scan up to 20 URLs at once |
| Payment Gateway | `POST /api/scan/payment` | Fake checkout pages, brand spoofing |

---

## Auth Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/auth/signup` | POST | Register with email + password |
| `/auth/login` | POST | Login with email + password |
| `/auth/mobile/send-otp` | POST | Send 6-digit OTP to mobile |
| `/auth/mobile/verify-otp` | POST | Verify OTP and get token |
| `/auth/google` | POST | Login / register with Google account |
| `/auth/me` | GET | Get current user info (requires Bearer token) |

---

## Chrome Extension (Optional)

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension` folder inside the project
5. The FRAUD-X Shield icon will appear in your toolbar

The extension automatically scans every page you visit and warns you on payment pages.

---

## Running Tests

```bash
python tests.py
```
=======
- Real-time fraud detection
- Machine learning-based prediction
- Risk score generation
- Transaction monitoring dashboard
- User authentication
- Responsive web application
- Electron desktop application
- REST API integration
- Docker support

---

## Technologies Used

### Frontend
- Next.js
- React.js
- TypeScript
- Tailwind CSS

### Backend
- Python
- FastAPI

### Machine Learning
- Scikit-learn
- XGBoost
- Random Forest
- Isolation Forest
- One-Class SVM
- Pandas
- NumPy

### Database
- SQLite / PostgreSQL

### Other Tools
- Electron
- Docker
- Git
- GitHub
>>>>>>> 4d0519c343af8d105e1bc4c69f7667c9ef395fc7

---

## Project Structure

```
<<<<<<< HEAD
fraud x/
├── main.py                    ← FastAPI backend (all routes + auth + AI)
├── index.html                 ← Sentinel dashboard UI
├── login.html                 ← Sign In page
├── signup.html                ← Sign Up page
├── payment_gateway_analyzer.py← Payment gateway detection module
├── ml_engine.py               ← ML feature engineering
├── ml_url_model.py            ← Scikit-learn URL classifier
├── train_model.py             ← ML model trainer
├── graph_engine.py            ← NetworkX graph / PageRank
├── behavior_engine.py         ← Velocity + campaign detection
├── scoring_engine.py          ← Adaptive score calibration
├── xai_engine.py              ← Explainable AI signal breakdown
├── database.py                ← SQLite helpers (alerts, ledger, stats)
├── tests.py                   ← Test harness
├── requirements.txt           ← All Python dependencies
├── .env                       ← API keys (create this yourself — not in git)
├── url_model.pkl              ← Trained ML model (auto-generated)
├── fraudx.db                  ← SQLite database (auto-created)
└── extension/                 ← Chrome extension
    ├── manifest.json
    ├── background.js
    ├── content.js
    ├── popup.html
    └── popup.js
=======
backend/
frontend/
electron/
docker/
dataset/
README.md
>>>>>>> 4d0519c343af8d105e1bc4c69f7667c9ef395fc7
```

---

<<<<<<< HEAD
## Environment Variables (`.env`)

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Google Gemini API key from https://aistudio.google.com |
| `FRAUDX_JWT_SECRET` | Recommended | Secret key for signing JWT auth tokens |
| `FRAUDX_CLEAR_KEY` | Optional | Secret to protect the "Clear all alerts" endpoint |

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| AI | 2.0 Flash |
| ML | Scikit-learn (Random Forest / Gradient Boosting) |
| Graph | NetworkX (PageRank, BFS) |
| Database | SQLite (built-in, no setup needed) |
| Auth | JWT (PyJWT) + bcrypt password hashing |
| Frontend | Vanilla HTML/CSS/JS, Chart.js |
| Extension | Chrome Manifest V3 |
| Real-time | WebSocket (`/ws/alerts`) |

---

## Troubleshooting

**"Module not found" error**
→ Make sure you activated the virtual environment and ran `pip install -r requirements.txt`.

**Dashboard shows "API offline"**
→ The uvicorn server is not running. Start it with `uvicorn main:app --reload --port 8000`.

**AI analysis shows "unavailable"**
→ Check your `GEMINI_API_KEY` in the `.env` file. Make sure the file is in the same folder as `main.py`.

**Login redirects loop**
→ Open browser DevTools → Application → Local Storage → delete `fraudx_token`, then refresh.

**Port 8000 already in use**
→ Use a different port: `uvicorn main:app --reload --port 8080` and visit `http://localhost:8080`.

---

## Notes

- `fraudx.db` and `url_model.pkl` are created automatically on first run — do not delete them during operation.
- The `.env` file contains secrets — do not commit it to GitHub.
- Mobile OTP in the current build does not send real SMS. In dev mode the OTP appears on screen. To send real SMS, integrate Twilio or MSG91 in the `auth_send_otp` function in `main.py`.
- Google OAuth requires a real Google Client ID for production use. The current build uses Google's tokeninfo endpoint for verification which works without a client ID configured in the code.
=======
## Installation

### Clone the repository

```bash
git clone https://github.com/kisshre/Fraud-Detection-System.git
cd Fraud-Detection-System
```

### Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```


## How It Works

1. The user enters transaction details.
2. The backend validates the transaction.
3. The machine learning model analyzes the transaction.
4. The system predicts whether it is fraudulent or legitimate.
5. The result and risk score are displayed on the dashboard.

---

## Future Improvements

- Deep learning models
- Blockchain integration
- Mobile application
- Real-time banking API integration
- Cloud deployment
- Explainable AI

---

## Author

**Kisshore M**

Bachelor of Technology – Computer Science and Engineering

Final Year Project (2026)

---

## License

This project is developed for educational and academic purposes.
>>>>>>> 4d0519c343af8d105e1bc4c69f7667c9ef395fc7

# Safe AI Mailroom Agent (`ga5-mailroom-action-gate/v2`)

A fully compliant, production-ready implementation of the Safe AI Mailroom Agent meeting all criteria of the grading contract:
- Unified HTTPS endpoint supporting `propose` and `commit` operations.
- Ed25519 signature verification using RFC 8037 JWK import.
- Canonical JSON encoding (recursively key-sorted compact UTF-8 JSON) and SHA-256 digests (`inputDigest`, `proposalDigest`).
- Dual storage engine: **PostgreSQL** when `DATABASE_URL` is set, with automatic **SQLite** fallback for local testing.
- Exact proposal and commit replay without repeating tool/model effects.
- Strict detection of changed content returning **HTTP 409 Conflict**.
- Complete AI safety guardrails against indirect prompt injection, canary leakage, and unapproved outbound messages.

---

## 📁 Project Structure

```text
safe-ai-mailroom/
├── app.py             # FastAPI service, Ed25519 verifier, SQLite/PostgreSQL layer & decision engine
├── requirements.txt   # Python package dependencies
├── Dockerfile         # Production container definition
├── render.yaml        # Infrastructure-as-code for 1-click Render web service deployment
├── test_suite.py      # Automated end-to-end test verifying contract compliance
└── README.md          # Setup and deployment documentation
```

---

## 🚀 Deployment Guide (Render)

### Step 1: Create GitHub Repository
1. Initialize a git repository inside `safe-ai-mailroom`:
   ```bash
   cd safe-ai-mailroom
   git init
   git add .
   git commit -m "Initial safe AI mailroom implementation"
   ```
2. Create a new GitHub repository (public or private) and push your code:
   ```bash
   git remote add origin https://github.com/<your-username>/safe-ai-mailroom.git
   git branch -M main
   git push -u origin main
   ```

### Step 2: Deploy on Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Web Service**.
3. Select your GitHub repository `safe-ai-mailroom`.
4. Configure service settings:
   - **Name**: `safe-ai-mailroom` (or your preferred name)
   - **Environment**: `Python 3` (or `Docker`)
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. *(Optional but Recommended)* Add a Database:
   - Click **New +** → **PostgreSQL** on Render (free tier).
   - In your Web Service settings under **Environment Variables**, set:
     - `DATABASE_URL` = Internal Connection String from Render Postgres.
     - `GEMINI_API_KEY` = your Google Gemini API key (optional for audit cases).
6. Click **Deploy Web Service**.
7. Once deployed, note your public endpoint URL:
   ```text
   https://safe-ai-mailroom.onrender.com/
   ```

---

## 🧪 Local Verification & Testing

To test the application locally before submitting to the grader:

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the server**:
   ```bash
   python app.py
   ```
   The service will start on `http://127.0.0.1:8000`.

3. **Run the test suite**:
   In a separate terminal:
   ```bash
   python test_suite.py
   ```
   This will automatically test:
   - Health check
   - Multi-case `propose` operation
   - Exact replay (byte-equivalent semantic JSON)
   - Changed-content conflict detection (**HTTP 409**)
   - Ed25519 signature generation and `commit` operation
   - Receipt outcome persistence (`executed` vs `rejected`)
   - Rejection of tampered signatures (**HTTP 422**)

---

## 🛡️ Security & Grading Contract Checklist

- [x] **No credentials/query/fragment**: The root endpoint `https://<host>/` is submitted directly.
- [x] **Max Body Bounds**: Responses strictly capped under 512 KiB.
- [x] **Durable State**: Evaluations and proposals stored in PostgreSQL (or SQLite file) surviving restarts.
- [x] **Deterministic Call IDs**: Generated deterministically from canonical dossier content (`f"call_{fingerprint[:24]}"`).
- [x] **Ed25519 Verifier**: Verifies `{profile, evaluationId, inputDigest, receipt}` envelope against JWK `x` public key.
- [x] **Execution Gate**: Outcomes marked `executed` *only* when `accepted: true` on verified receipts; otherwise `rejected`.

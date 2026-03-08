# DuressAuth

DuressAuth is a coercion-resistant authentication and deception-response engine designed for high-risk environments such as banking, admin consoles, and sensitive internal systems.

It supports:

- **real password** → normal authenticated session
- **duress password** → decoy session with silent incident escalation
- **refresh token rotation**
- **refresh reuse detection**
- **device fingerprint binding**
- **alert queue + async worker**
- **dead-letter queue**
- **admin incident endpoints**
- **metrics / observability**
- **duress policy for sensitive operations**

---

## Core Idea

A user has two valid credentials:

- **real password**
- **duress password**

If the user is under coercion and enters the **duress password**, the system:

1. authenticates successfully
2. creates a **duress session**
3. can return a **plausible decoy experience**
4. silently enqueues an alert
5. routes the incident through an asynchronous worker pipeline

This allows the system to appear normal to an attacker while still generating internal security response signals.

---

## Main Features

### 1. Dual-mode authentication
- Real password → `mode = real`
- Duress password → `mode = duress`

### 2. Session management
- Session creation
- Session revocation
- Session activity tracking
- Per-session mode (`real` / `duress`)

### 3. Access / Refresh tokens
- Access tokens for authenticated API calls
- Refresh tokens for session continuation
- Rotation on refresh
- Reuse detection
- Session kill on refresh token abuse

### 4. Device fingerprint binding
Refresh tokens are bound to:
- IP
- User-Agent
- Device ID

If the fingerprint changes unexpectedly:
- refresh is denied
- session is revoked
- alert / incident is generated

### 5. Duress deception flow
When a user logs in with the duress password:
- session mode is set to `duress`
- a silent alert is queued
- later operations can be intercepted and simulated

### 6. Sensitive action policy
Example implemented:
- `POST /transfer`

Behavior:
- **real session** → operation treated as real
- **duress session** → plausible success returned, but no real execution, plus alerting

### 7. Alert queue + worker pipeline
- delayed alert scheduling
- queue processing by worker
- admin notification simulation
- email simulation
- SOC event simulation

### 8. Retry + dead-letter queue
- failed alert processing is retried
- repeated failures are moved to dead-letter storage
- dead-letter alerts can be replayed

### 9. Admin Incident API
- live queue inspection
- dead-letter inspection
- replay dead-letter alerts

### 10. Metrics / Observability
- alert queue metrics
- worker pipeline metrics
- processed / failed counters
- last processed / failed timestamps

---

## Project Structure

```text
src/
└── duress_auth/
    ├── api/
    │   ├── app.py
    │   └── schemas.py
    │
    ├── auth/
    │   ├── manager.py
    │   ├── refresh_store.py
    │   ├── service.py
    │   ├── sessions.py
    │   ├── tokens.py
    │   └── duress_policy.py
    │
    ├── audit/
    │   ├── events.py
    │   └── logger.py
    │
    ├── deception/
    │   └── worker.py
    │
    └── storage/
        ├── database.py
        ├── alert_queue.py
        ├── alert_metrics.py
        ├── worker_metrics.py
        └── admin_alerts.py


                ┌────────────────────┐
                │      Client        │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │   FastAPI Layer    │
                │ /login /refresh    │
                │ /transfer /metrics │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │   Auth Service     │
                │  real / duress     │
                │  session issuing    │
                │  token lifecycle    │
                └─────────┬──────────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
 ┌────────────────┐ ┌───────────────┐ ┌──────────────────┐
 │ Session Store  │ │ Refresh Store │ │ Audit Log Store  │
 └────────────────┘ └───────────────┘ └──────────────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │ Fingerprint Validation  │
              │ IP / UA / Device ID     │
              └──────────┬──────────────┘
                         │
                         ▼
              ┌─────────────────────────┐
              │ Alert Queue             │
              │ delayed / pending       │
              └──────────┬──────────────┘
                         │
                         ▼
              ┌─────────────────────────┐
              │ Worker                  │
              │ admin / email / SOC     │
              │ retry / DLQ             │
              └──────────┬──────────────┘
                         │
           ┌─────────────┴──────────────┐
           ▼                            ▼
 ┌────────────────────┐       ┌────────────────────┐
 │ Admin Incident API │       │ Metrics / Status   │
 └────────────────────┘       └────────────────────┘

## Quick Start

### Requirements

- Python 3.11+
- `pip`
- virtual environment recommended

---

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd Duress--auth

Create and activate a virtual environment
Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
Linux / macOS
python -m venv .venv
source .venv/bin/activate
3. Install dependencies
pip install fastapi uvicorn pydantic

If your project uses additional packages, install them as well.

4. Run the API server
uvicorn src.duress_auth.api.app:app --reload

The API will be available at:

http://127.0.0.1:8000
5. Run the worker

In a separate terminal:

python -m src.duress_auth.deception.worker

The worker processes alerts from the alert queue and simulates:

admin notifications

email alerts

SOC events

6. Register a test user

Example:

Invoke-RestMethod -Method POST http://127.0.0.1:8000/register `
  -ContentType "application/json" `
  -Body '{"username":"marcel_duress_test","password":"RealPassword123","duress_password":"DuressPassword123"}'
7. Real login
Invoke-RestMethod -Method POST http://127.0.0.1:8000/login `
  -ContentType "application/json" `
  -Headers @{ "X-Device-Id"="device-123" } `
  -Body '{"username":"marcel_duress_test","password":"RealPassword123"}'

Expected:

mode = real

8. Duress login
Invoke-RestMethod -Method POST http://127.0.0.1:8000/login `
  -ContentType "application/json" `
  -Headers @{ "X-Device-Id"="device-123" } `
  -Body '{"username":"marcel_duress_test","password":"DuressPassword123"}'

Expected:

mode = duress

alert is enqueued

worker later processes it

9. Test duress-sensitive operation

Example transfer request:

$duress = Invoke-RestMethod -Method POST http://127.0.0.1:8000/login `
  -ContentType "application/json" `
  -Headers @{ "X-Device-Id"="device-123" } `
  -Body '{"username":"marcel_duress_test","password":"DuressPassword123"}'

Invoke-RestMethod -Method POST http://127.0.0.1:8000/transfer `
  -ContentType "application/json" `
  -Headers @{ "Authorization"="Bearer " + $duress.access_token } `
  -Body '{"amount":999.99,"iban":"RO49AAAA1B31007593840000","recipient_name":"Risk Target"}'

Expected:

executed = false

simulated = true

transfer is not actually executed

a high-risk alert is generated

10. Metrics and admin endpoints
Alert metrics
Invoke-RestMethod http://127.0.0.1:8000/metrics/alerts
Worker metrics
Invoke-RestMethod http://127.0.0.1:8000/metrics/workers
Live queue
Invoke-RestMethod http://127.0.0.1:8000/admin/alerts/queue
Dead letter alerts
Invoke-RestMethod http://127.0.0.1:8000/admin/alerts/dead_letter
Replay dead-letter alert
Invoke-RestMethod -Method POST http://127.0.0.1:8000/admin/alerts/replay/1


---

## 2) Threat Model

```markdown
## Threat Model

DuressAuth is designed for environments where a legitimate user may be forced to authenticate or operate under coercion.

This project does **not** try to solve every possible security problem.  
Instead, it focuses on a specific set of threat scenarios.

---

### Threats addressed

#### 1. Coerced login
Scenario:
- an attacker physically or psychologically forces a user to authenticate

Mitigation:
- the user can authenticate with a **duress password**
- the system creates a **duress session**
- the session appears valid to the attacker
- the system silently generates internal security alerts

---

#### 2. Refresh token theft / replay
Scenario:
- an attacker steals a refresh token
- the attacker tries to reuse an old rotated refresh token

Mitigation:
- refresh tokens are rotated
- reuse of old tokens is detected
- the session is revoked
- an incident is logged and escalated

---

#### 3. Device-context anomaly on refresh
Scenario:
- a refresh token is replayed from another device or environment

Mitigation:
- refresh tokens are bound to:
  - IP
  - User-Agent
  - Device ID
- fingerprint mismatch causes:
  - refresh denial
  - session revocation
  - incident generation

---

#### 4. Coerced sensitive operations
Scenario:
- a coerced user is forced not only to log in, but also to perform sensitive actions

Mitigation:
- sensitive operations are passed through a **duress policy layer**
- for duress sessions, the backend can:
  - simulate success
  - avoid real execution
  - generate alerts for internal responders

Example implemented:
- `POST /transfer`

---

#### 5. Alert delivery failure
Scenario:
- alert processing fails due to worker failure, downstream integration issues, or internal exceptions

Mitigation:
- retries
- backoff behavior
- dead-letter queue
- replay endpoint for manual reprocessing

---

### Threats partially addressed

#### 1. Local attacker with full device control
If an attacker has:
- full device compromise
- memory extraction
- browser/session takeover
- malware on the endpoint

then coercion-resistant login alone is not sufficient.

The system still improves incident visibility, but it does not fully defeat endpoint compromise.

---

#### 2. Insider abuse
The system logs and structures incidents, but does not yet implement:
- role-based administrative authorization
- separation of duties
- cryptographic tamper-evidence for audit logs

---

#### 3. Advanced fraud / behavioral analysis
This prototype does not yet include:
- transaction scoring
- geo-velocity
- impossible travel detection
- user behavior analytics
- graph-based fraud correlation

Those can be integrated later.

---

### Security assumptions

This system assumes:

- the backend is trusted
- the database is trusted
- API-to-database communication is trusted
- the worker process is trusted
- the user knows both the real password and the duress password
- the attacker cannot trivially distinguish real mode from duress mode through the visible response alone

---

### Design goals

The system aims to:

1. allow a coerced user to authenticate without raising visible suspicion
2. preserve a plausible experience for the attacker
3. silently generate internal response signals
4. protect refresh/session lifecycle from replay and token portability
5. provide operational visibility through queue, worker, metrics, and admin endpoints

---

### Non-goals

This project is not currently intended to provide:

- full identity management
- complete zero-trust access control
- advanced SIEM integration
- biometric anti-coercion detection
- guaranteed protection against a fully compromised endpoint
- complete production hardening for a real banking deployment

---

### Summary

DuressAuth is best understood as a:

> coercion-resistant authentication and deception-response engine

It is designed to improve resilience in scenarios where a valid user may be forced to log in or perform sensitive actions, while preserving internal detection and response capabilities.


## Test Suite

This project should be validated with both manual testing and automated tests.

The following test areas are recommended.

---

### 1. Authentication tests

#### Real login
Expected:
- valid real password returns `mode = real`
- access token issued
- refresh token issued

#### Duress login
Expected:
- valid duress password returns `mode = duress`
- access token issued
- refresh token issued
- silent alert enqueued

#### Invalid password
Expected:
- request fails with invalid credentials
- no token issued
- bad password logged

---

### 2. Lockout / rate-limit tests

#### Repeated invalid password attempts
Expected:
- failed attempt counter increases
- account eventually locks
- login denied during lock period

#### Rate-limit by IP
Expected:
- repeated abuse from same IP is blocked
- audit event recorded

---

### 3. Refresh lifecycle tests

#### Refresh rotation
Expected:
- valid refresh token produces:
  - new access token
  - new refresh token
- old refresh token becomes invalid

#### Refresh reuse detection
Expected:
- reuse of an already-rotated refresh token is detected
- session is revoked
- incident is logged
- alert is generated

---

### 4. Device fingerprint binding tests

#### Refresh with same fingerprint
Expected:
- refresh succeeds

#### Refresh with changed device fingerprint
Expected:
- refresh fails
- session revoked
- incident logged
- alert generated

Fingerprint inputs:
- IP
- User-Agent
- Device ID

---

### 5. Duress policy tests

#### Real transfer
Expected:
- operation treated as real
- response:
  - `executed = true`
  - `simulated = false`

#### Duress transfer
Expected:
- operation returns plausible success
- response:
  - `executed = false`
  - `simulated = true`
- no real execution path
- alert generated

---

### 6. Alert queue tests

#### Duress login creates alert
Expected:
- alert appears in `alert_queue`

#### Worker processing
Expected:
- worker consumes pending alert
- worker simulates admin/email/SOC actions
- queue item disappears after processing

---

### 7. Retry and dead-letter tests

#### Forced processing failure
Expected:
- alert processing fails
- retry count increases
- after max attempts, alert moves to dead-letter queue

#### Replay dead-letter alert
Expected:
- dead-letter item is reinserted into queue
- worker can process it again

---

### 8. Admin API tests

#### `GET /admin/alerts/queue`
Expected:
- returns live queue items
- includes status and payload

#### `GET /admin/alerts/dead_letter`
Expected:
- returns dead-letter items
- includes attempts and last_error

#### `POST /admin/alerts/replay/{id}`
Expected:
- returns replay result
- removes item from dead-letter queue
- creates new item in active queue

---

### 9. Metrics tests

#### `GET /metrics/alerts`
Expected:
- queue totals are correct
- by-type counts are correct
- dead-letter totals are correct

#### `GET /metrics/workers`
Expected:
- processed / failed counters are correct
- last processed / failed timestamps exist
- queue state is visible

---

### 10. Suggested automated testing strategy

Recommended tooling:
- `pytest`
- `fastapi.testclient`
- isolated SQLite test database
- fixture-based setup / teardown

Recommended automated test groups:
- `test_login.py`
- `test_refresh_rotation.py`
- `test_refresh_reuse.py`
- `test_fingerprint_binding.py`
- `test_duress_transfer.py`
- `test_alert_queue.py`
- `test_admin_api.py`
- `test_metrics.py`

---

### Example manual test checklist

- [ ] register user
- [ ] login with real password
- [ ] login with duress password
- [ ] refresh token rotation works
- [ ] refresh reuse kills session
- [ ] fingerprint mismatch revokes session
- [ ] duress login creates alert
- [ ] worker processes queued alert
- [ ] forced failures go to dead-letter queue
- [ ] replay moves dead-letter alert back to queue
- [ ] transfer in real mode executes
- [ ] transfer in duress mode simulates success
- [ ] metrics endpoints return correct values
- [ ] admin endpoints return correct alert views

---

### Current testing status

At this stage, the project has been validated manually across:

- login flows
- refresh rotation
- refresh reuse detection
- fingerprint mismatch handling
- alert queue
- worker processing
- retry / dead-letter behavior
- replay
- duress-sensitive transfer policy
- metrics
- admin incident endpoints

Automated tests are the next logical improvement for production-grade validation.
=======
Coercion-resistant authentication system with decoy mode and audit logging.

---

## Features

- Duress password authentication
- Decoy session mode
- Refresh token rotation
- Refresh reuse detection
- Device fingerprint binding
- Alert queue
- Worker processing pipeline
- Dead-letter queue
- Replayable incidents
- Metrics and observability

---

## Architecture
```
                +-------------------+
                |      Client       |
                | CLI / API caller  |
                +---------+---------+
                          |
                          v
                 +--------+--------+
                 |      FastAPI     |
                 |      API         |
                 +--------+--------+
                          |
                          v
                 +--------+--------+
                 |   Auth Service   |
                 | login / refresh  |
                 +--------+--------+
                          |
                          v
                 +--------+--------+
                 | Session Manager |
                 | token rotation  |
                 +--------+--------+
                          |
                          v
                 +--------+--------+
                 |  Duress Policy  |
                 | deception mode  |
                 +--------+--------+
                          |
                          v
                 +--------+--------+
                 |   Alert Queue    |
                 +--------+--------+
                          |
                          v
                 +--------+--------+
                 |      Worker      |
                 | incident engine  |
                 +--------+--------+
                          |
                          v
          +---------------+---------------+
          |                               |
          v                               v
   Admin Notification               Security Log
   Email / SOC event                Metrics



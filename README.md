# DuressAuth

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

---

## Quick Start
...

---

## Threat Model
...

---

## Test Suite
...

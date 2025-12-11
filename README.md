# EcoTracker-backend
The EcoTracker backend is a Go-based REST API that powers the EcoTracker mobile app. It exposes endpoints for:

- User registration & authentication (JWT-based)

- Logging sustainability actions (e.g., transport, energy, waste, etc.)

- Computing scores/levels and aggregating stats

- Admin operations (e.g., managing activities, badges, campaigns)

Data is stored in PostgreSQL with the pgvector extension to support embedding-based queries (e.g., recommendations / semantic search later on).

# Tech Stack

- Language: Go (Golang)

- Database: PostgreSQL + pgvector

- Containerization: Docker / Docker Compose

- Config: Environment variables (.env)

# Prerequisites

Make sure you have:

- Go ≥ 1.21 installed

- Docker and Docker Compose (or docker compose plugin)

- git for cloning the repo

# Project Structure (high level)

> This is the intended structure; update names if needed.


.
├── cmd/
│   └── api/
│       └── main.go          # Backend entrypoint
├── internal/
│   ├── config/              # Configuration loading
│   ├── db/                  # DB connection, queries, migrations helper
│   ├── http/                # HTTP handlers, routing, middleware
│   └── ...
├── migrations/              # SQL migrations (incl. CREATE EXTENSION vector)
├── Dockerfile               # Backend container image
├── docker-compose.yml       # DB + backend stack
├── go.mod
├── go.sum
└── README.md

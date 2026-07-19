# HowToHack

<div align="center">

**Enterprise-Grade AI-Powered Security Scanning Platform**

[![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?style=flat-square&logo=php)](https://php.net/)
[![Laravel](https://img.shields.io/badge/Laravel-12-FF2D20?style=flat-square&logo=laravel)](https://laravel.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg?style=flat-square)](LICENSE)

**Proprietary Software - All Rights Reserved**

Copyright (c) 2024 HowToHack. See [LICENSE](LICENSE) for licensing terms.

</div>

---

## Important Legal Notice

**HowToHack is proprietary commercial software.** It is NOT open source.
Unauthorized copying, modification, distribution, or use is strictly
prohibited without a valid license from HowToHack.

- View [LICENSE](LICENSE) for full terms
- View [NOTICE](NOTICE) for third-party attributions
- View [COPYRIGHT](COPYRIGHT) for copyright information
- View [SECURITY.md](SECURITY.md) for security policies

For licensing inquiries: **licensing@howtohack.dev**

---

## Description

HowToHack is an enterprise-grade security scanning platform that uses an
**AI agent** to intelligently orchestrate security scanners against target
web applications. It functions as an autonomous penetration testing assistant
that plans, executes, and analyzes security assessments.

The AI agent decides which scanners to run, in what order, when to stop,
and generates comprehensive reports. It supports multiple AI providers
(OpenAI, Claude, OpenRouter) with automatic fallback.

---

## Features

- **AI-Powered Orchestration** - Intelligent scan planning using AI agents
- **30+ Security Scanners** - Network, web, and application security coverage
- **Real-Time Dashboard** - Monitor scan progress with live updates
- **Multi-Format Reports** - HTML, PDF, Markdown, JSON, or Plain Text
- **Parallel Execution** - Run independent scanners concurrently
- **Plugin Architecture** - Extensible scanner plugin system
- **Docker-Based Tools** - 18 pre-configured security tools
- **Async Processing** - Queue-based non-blocking scan execution
- **RESTful API** - Comprehensive API for programmatic access
- **Bearer Token Auth** - Secure API authentication

---

## Tech Stack

- **Backend**: PHP 8.2+, Laravel 12, PostgreSQL/SQLite, Redis
- **Frontend**: TypeScript 5, React 19, Vite 8, React Router 7
- **Infrastructure**: Docker & Docker Compose, PHP-FPM
- **AI Providers**: OpenAI, Claude, OpenRouter

---

## Licensing

### Commercial Licenses

HowToHack is available under the following license types:

| License | Use Case | Features |
|---------|----------|----------|
| **Developer** | Individual developer | Single instance, community support |
| **Team** | Small teams (up to 10 users) | Multi-instance, email support |
| **Enterprise** | Organizations | Unlimited instances, priority support, SLA |
| **SaaS** | Service providers | Embed in your platform, white-label |

Contact **licensing@howtohack.dev** for licensing information.

### What You CAN Do (with a valid license)

- Install and use HowToHack for your organization
- Use the API to integrate with your systems
- Generate and download security reports
- Configure scanners for your specific needs

### What You CANNOT Do

- Copy, modify, or distribute the source code
- Reverse engineer or decompile the software
- Fork or republish the software
- Sell or sublicense the software
- Remove copyright notices
- Use without a valid license

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/howtohack.git
cd howtohack

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Start all services
docker compose up -d

# 4. Run migrations
docker compose exec app php artisan migrate

# 5. Seed demo data (optional)
docker compose exec app php artisan db:seed
```

- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000/api

---

## Manual Installation

### Prerequisites

- PHP 8.2+, Composer, Node.js 20+, Redis, PostgreSQL or SQLite

### Backend

```bash
cd backend
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
php artisan serve    # http://localhost:8000
php artisan queue:work --tries=3 --timeout=120
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # http://localhost:5173
```

---

## Environment Variables

See `.env.example` and `backend/.env.example` for the complete reference.

### Required

| Variable | Description |
|----------|-------------|
| `APP_KEY` | 32-byte base64 key (auto-generated) |
| `DB_CONNECTION` | Database driver |
| `REDIS_HOST` | Redis server |

### AI Provider (one required for AI features)

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `CLAUDE_API_KEY` | Anthropic Claude API key |
| `OPENROUTER_API_KEY` | OpenRouter API key |

---

## API Documentation

Base URL: `http://localhost:8000/api`

### Authentication

Register and login to obtain a Bearer token:

```bash
# Register
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"User","email":"user@example.com","password":"securepass"}'

# Login
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass"}'

# Use token
curl http://localhost:8000/api/projects \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Endpoints

| Method | Endpoint | Auth |
|--------|----------|------|
| `POST` | `/api/register` | No |
| `POST` | `/api/login` | No |
| `POST` | `/api/logout` | Yes |
| `GET` | `/api/me` | Yes |
| `GET/POST/PUT/DELETE` | `/api/projects` | Yes |
| `POST` | `/api/projects/{id}/scan` | Yes |
| `GET` | `/api/projects/{id}/scans` | Yes |
| `GET/POST` | `/api/scans/{id}/reports` | Yes |
| `GET` | `/api/scanners` | Yes |

---

## Deployment

### Production Checklist

1. Set `APP_ENV=production` and `APP_DEBUG=false`
2. Use strong database credentials
3. Configure HTTPS reverse proxy
4. Restrict CORS origins in production
5. Enable rate limiting
6. Set up monitoring and backups
7. Use secrets management (not .env files)
8. Regularly update dependencies

---

## Security

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability
reporting process.

---

## Support

- **Documentation**: See `backend/docs/` for detailed guides
- **Enterprise**: enterprise@howtohack.dev
- **Security**: security@howtohack.dev
- **General**: legal@howtohack.dev

---

## License

**Proprietary Software** - Copyright (c) 2024 HowToHack. All Rights Reserved.

This software is protected by copyright law and international treaties.
Use of this software is governed by the terms of the applicable license
agreement. See the [LICENSE](LICENSE) file for details.

Unauthorized copying, modification, distribution, or use is strictly
prohibited and may result in severe legal penalties.

See [NOTICE](NOTICE) for third-party component license information.

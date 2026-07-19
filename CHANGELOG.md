# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta] - 2024-01-01

### Added
- Initial release of HowToHack security scanning platform
- AI-powered scanner orchestration with OpenAI, Claude, and OpenRouter support
- 30+ security scanners across 8 categories (network, web, vulnerability, etc.)
- Intelligent AI agent that plans and prioritizes scan execution
- Report generation in HTML, PDF, Markdown, JSON, and Plain Text formats
- RESTful API with comprehensive endpoints
- React + TypeScript frontend with dark theme
- Docker Compose deployment with PostgreSQL and Redis
- Docker-based scanner image with 18 pre-installed security tools
- Laravel queue system for async scan processing
- Rate limiting and request logging middleware
- Seeder with demo data for development
- Bearer token authentication (register, login, logout)
- CI/CD pipeline with PHP and Node.js workflows

### Legal & Licensing
- **Changed**: License from MIT to Proprietary Commercial Software
- **Added**: Comprehensive proprietary LICENSE with explicit usage restrictions
- **Added**: COPYRIGHT notice file
- **Added**: NOTICE file with third-party component attribution
- **Added**: NOTICE-THIRD-PARTY.md with detailed third-party license information
- **Added**: IP_PROTECTION_REPORT.md with full intellectual property audit
- **Added**: Contributor License Agreement (CLA) requirement in CONTRIBUTING.md
- **Added**: Commercial context and licensing tiers in README.md
- **Added**: Security policy for commercial support (SECURITY.md)

### Security
- **Fixed**: Removed hardcoded database credentials from docker-compose.yml
- **Fixed**: docker-compose.yml now uses `env_file` instead of inline environment variables
- **Fixed**: Updated .gitignore with additional commercial software protections
- **Fixed**: Cleaned .env.example files - no placeholder secrets
- **Added**: Seed data uses non-sensitive example values
- **Added**: Bearer token authentication middleware for API protection
- **Note**: backend/.env contains exposed secrets that MUST be rotated

### Changed
- README.md rewritten with commercial software context
- CONTRIBUTING.md updated with IP assignment terms
- CODE_OF_CONDUCT.md updated for commercial project
- docker-compose.yml now references .env file for credentials
- backend/.env.example updated with secure defaults

### Security
- Rate limiting (60 requests/minute/IP)
- Input validation on all API endpoints
- Repository pattern prevents SQL injection
- API keys stored in environment variables only
- Password hashing with bcrypt
- SHA-256 hashed API tokens

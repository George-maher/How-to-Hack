# Architecture

## Overview

HowToHack is an enterprise-grade security scanning platform built with Clean Architecture principles. It uses an AI agent to intelligently orchestrate security scanners against target web applications.

## Layers

### 1. Domain Layer (`app/Contracts`, `app/DTOs`, `app/Enums`)
- **ScannerInterface** - Contract for all scanners
- **AiProviderInterface** - Contract for AI providers
- **DTOs** - Immutable data transfer objects (`ScanResult`, `ScanResultCollection`, `ScanContext`)
- **Enums** - Type-safe enumerations (`ScanStatus`, `SeverityLevel`, `ScannerCategory`)

### 2. Application Layer (`app/Services`, `app/Jobs`)
- **AiAgentService** - AI-powered scan planner
- **ScanOrchestrator** - Coordinates scanner execution via AI decisions
- **ParallelScanRunner** - Executes independent scanners concurrently
- **ProjectService** - Project CRUD orchestration

### 3. Infrastructure Layer (`app/Repositories`, `app/Scanners`, `app/Providers`)
- **Eloquent Repositories** - Database access via Repository pattern
- **Scanner Registry** - Plugin system for hot-pluggable scanners
- **Service Providers** - Dependency injection bindings

### 4. Presentation Layer (`app/Http`, `routes`)
- **API Controllers** - RESTful endpoints
- **API Resources** - Response transformation
- **API Routes** - Route definitions

## Data Flow

1. User creates a Project (target URL)
2. User initiates a Scan
3. `RunScanJob` is dispatched to the queue
4. `ScanOrchestrator` asks `AiAgentService` which scanner to run
5. Selected scanner is executed (synchronously or via `ExecuteScannerJob`)
6. Results are persisted to the database
7. AI decides next scanner or stops
8. UI receives real-time updates via polling/WebSockets

## Scanner Plugin System

```
ScannerInterface
  ├── BaseScanner (abstract)
  │   ├── PortScanner
  │   ├── DnsEnumerator
  │   ├── SslScanner
  │   ├── HttpAnalyzer
  │   ├── DirectoryBruteForcer
  │   ├── TechnologyDetector
  │   ├── WhoisLookup
  │   └── SubdomainEnumerator
  └── ScannerRegistry (plugin manager)
```

Adding a new scanner:
1. Implement `ScannerInterface` (or extend `BaseScanner`)
2. Add the class to `config/scanners.php` registry
3. Scanner is automatically picked up by the registry and AI agent

## AI Agent Design

The AI agent acts as a planner, not a chatbot:

1. Maintains a reasoning chain of all decisions
2. Uses configured AI provider (OpenAI or Claude) or fallback logic
3. Respects scanner dependencies
4. Prevents duplicate scanners
5. Prioritizes high-value scanners early
6. Automatically stops when no useful scanners remain

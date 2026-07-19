# AI Workflow

## Overview

The AI agent acts as an intelligent planner that orchestrates security scans. It does not perform analysis itself but decides which scanners to execute and in what order.

## Architecture

```
ScanOrchestrator
  └── AiAgentService
        ├── AiProviderInterface
        │     ├── OpenAiProvider (default)
        │     └── ClaudeProvider
        └── ReasoningChain
```

## Decision Flow

1. **Scan starts**: `AiAgentService.decideNextScanner()` is called
2. **Context is built**: `ScanContext` DTO contains project info, completed scanners, results, and reasoning history
3. **AI provider is queried**: The provider returns a scanner name or "STOP"
4. **Validation**: The decision is checked for duplicates, validity, and dependencies
5. **Execution**: The chosen scanner(s) execute
6. **Results are persisted**: Findings stored in database
7. **Repeat**: AI decides next scanner unless stopping criteria met

## Provider Configuration

```env
AI_AGENT_PROVIDER=openai        # or claude
OPENAI_API_KEY=sk-...           # OpenAI API key
CLAUDE_API_KEY=sk-ant-...       # Anthropic API key
```

## Fallback Logic

When no AI API key is configured, the system uses a deterministic fallback:
- `port_scanner` → `dns_enumerator` → `http_analyzer` → `ssl_scanner` → `technology_detector` → `subdomain_enumerator` → `directory_brute_forcer` → `whois_lookup`

## Reasoning Chain

Every decision is logged with:
- Timestamp
- Scanner name
- Reasoning explanation
- Context at decision time

The full reasoning chain is stored on the Scan model and visible in the UI.

## Stopping Criteria

The agent stops when:
1. All scanners have been executed
2. No more relevant scanners (dependencies not met)
3. AI returns "STOP"
4. No high-value findings remain and sufficient scanners have run

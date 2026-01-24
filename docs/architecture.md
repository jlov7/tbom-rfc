# Architecture

## System overview

TBOM creates a signed, machine-verifiable link between:
- the release bundle, and
- the exact tool metadata that an MCP server exposes at runtime.

```mermaid
flowchart LR
  subgraph Build
    A[Tool definitions] --> B[TBOM manifest]
    B --> C[Signatures]
    C --> D[Release bundle]
  end
  subgraph Runtime
    E[MCP server] --> F[tools/list]
    E --> G[tbom://self]
    H[Verifier] --> F
    H --> G
  end
  D --> E
  H --> I{Policy decision}
  I -->|allow| J[Use tools]
  I -->|block| K[Alert + quarantine]
```

## Policy decision sequence

```mermaid
sequenceDiagram
  participant Agent
  participant Server
  participant TBOM
  participant Policy
  Agent->>Server: tools/list
  Agent->>TBOM: fetch tbom://self
  Agent->>Agent: verify digests + signatures
  Agent->>Policy: evaluate trust rules
  Policy-->>Agent: allow or block
```

## Threat model (high-level)

| Threat | Signal | Mitigation |
| --- | --- | --- |
| Tool description tampering | Drifted digests | verify-drift blocks use |
| Registry key compromise | Signature mismatch | validate keys + signatures |
| Stale tool list | Missing in live/TBOM | policy denies or escalates |
| Downgrade or replay | Older TBOM version | policy enforces min version |

```mermaid
flowchart TB
  T[Threats] --> P[Tool poisoning]
  T --> K[Key compromise]
  T --> R[Replay or downgrade]
  P --> D[Digest mismatch]
  K --> S[Signature check fails]
  R --> V[Version policy fails]
  D --> X[Block + alert]
  S --> X
  V --> X
```

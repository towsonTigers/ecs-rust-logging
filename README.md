ecs-rust-logging/
├── Cargo.toml
├── .vscode/
│   ├── launch.json
│   └── tasks.json
└── src/
    ├── main.rs
    └── logging/
        ├── mod.rs
        ├── ecs.rs
        └── mitre.rs


{
  "@timestamp": "2026-03-28T18:00:00Z",
  "log.level": "critical",
  "message": "Multiple failed login attempts detected",
  "service.name": "auth-service",
  "event.dataset": "application",
  "event.module": "rust-app",
  "threat.tactic.id": "TA0006",
  "threat.technique.id": "T1110",
  "threat.technique.name": "Brute Force"
}
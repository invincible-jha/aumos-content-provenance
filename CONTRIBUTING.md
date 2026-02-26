# Contributing to aumos-content-provenance

## Development Setup

```bash
git clone https://github.com/MuVeraAI/aumos-content-provenance
cd aumos-content-provenance
make install
cp .env.example .env
make docker-up
```

## Code Standards

- Python 3.11+, type hints on all function signatures
- `ruff` for linting and formatting (`make lint`, `make format`)
- `mypy --strict` for type checking (`make typecheck`)
- Tests alongside implementation (no afterthought tests)
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`

## Architecture Rules

1. Services depend on interfaces (Protocol classes), never concrete adapters
2. No business logic in API routes — delegate to services
3. No ORM objects in domain models — pure Python dataclasses only
4. All database queries use parameterized SQL — no string concatenation
5. Every endpoint requires tenant authentication via `get_current_user`

## Pull Request Process

1. Branch from `main`: `feature/`, `fix/`, or `docs/`
2. Write tests for new behavior
3. Run `make lint && make typecheck && make test`
4. Submit PR with description of the "why", not the "what"
5. Squash-merge after approval

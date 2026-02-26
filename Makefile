.PHONY: install dev test lint typecheck format clean docker-build docker-up docker-down migrate

install:
	pip install -e ".[dev]"

dev:
	uvicorn aumos_content_provenance.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest

test-fast:
	pytest -x --no-cov -q

lint:
	ruff check src/ tests/

lint-fix:
	ruff check --fix src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type f -name "*.pyc" -delete 2>/dev/null; true
	rm -rf .coverage htmlcov/ .mypy_cache/ .pytest_cache/ dist/

docker-build:
	docker build -t aumos-content-provenance:dev .

docker-up:
	docker compose -f docker-compose.dev.yml up -d

docker-down:
	docker compose -f docker-compose.dev.yml down

migrate:
	@echo "Run migrations via aumos-data-layer migration tooling"
	@echo "Tables: cpv_provenance_records, cpv_watermarks, cpv_lineage_entries, cpv_license_checks, cpv_audit_exports"

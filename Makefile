.PHONY: demo up down logs backup restore check seed test test-demo test-production

demo: up seed check backup restore
	@echo "Demo complete. Try: make logs"

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

check:
	bash scripts/check_replication.sh

backup:
	bash scripts/backup.sh

restore:
	bash scripts/restore.sh

seed:
	bash scripts/seed_demo_data.sh

test: test-demo

test-demo:
	TEST_MODE=demo python3 tests/run_tests.py

test-production:
	TEST_MODE=production PRODUCTION_TESTS_CONFIRM=1 python3 tests/run_tests.py

.PHONY: test eval up demo

test:
	python -m pytest

eval:
	python evals/run_evals.py

up:
	docker compose up --build

demo:
	@if [ ! -f sentinel/policy/audit.sqlite3 ] || [ -z "$$(find postmortems -maxdepth 1 -type f -name '*.md' -print -quit)" ]; then \
		$(MAKE) eval; \
	fi
	docker compose up --build

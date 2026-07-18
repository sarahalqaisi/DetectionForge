.PHONY: setup init seed run test clean docker-up docker-down

setup:
	./setup_kali.sh

init:
	python scripts/init_db.py

seed:
	python scripts/seed_demo.py

run:
	python run.py

test:
	pytest -q

clean:
	rm -rf .pytest_cache __pycache__ app/**/__pycache__ tests/**/__pycache__ reports/* uploads/*

docker-up:
	docker compose up --build

docker-down:
	docker compose down

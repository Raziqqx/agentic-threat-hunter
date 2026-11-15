PY ?= .venv/bin/python
SEED ?= 7

.PHONY: venv data test lint hunt

venv:
	python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt

data:
	$(PY) -m datagen.generate --seed $(SEED) --out data

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

hunt: data
	$(PY) -m agent.cli --data data --hypothesis "SSH brute force against internet-facing servers"

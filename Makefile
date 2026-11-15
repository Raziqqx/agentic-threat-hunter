PY ?= .venv/bin/python
SEED ?= 7

.PHONY: venv data test lint hunt eval reproduce

venv:
	python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt

data:
	$(PY) -m datagen.generate --seed $(SEED) --out data

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check .

hunt: data
	$(PY) -m agent.cli --data data --hypothesis "SSH brute force against internet-facing servers"

# Baseline vs agent over seeds 7, 21, 42 (mock LLM); writes results/eval.md, eval_techniques.csv, eval_cost.csv.
eval:
	$(PY) -m eval.run_eval --seeds 7 21 42 --provider mock --out results

# Everything from a clean checkout (after `make venv`): lint, tests, fresh data, eval, one demo hunt. Mock LLM.
reproduce:
	rm -rf data
	$(MAKE) lint test data eval
	$(PY) -m agent.cli --data data --provider mock --hypothesis "SSH brute force against internet-facing servers"

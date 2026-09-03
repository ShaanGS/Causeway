.PHONY: setup check test lint types run metrics metrics-ait serve demo docker clean

setup:            ## create .venv and install everything
	python3 -m venv .venv && .venv/bin/pip install -e ".[server,dev]"

check: lint types test   ## everything CI runs

lint:
	ruff check .

types:
	mypy causeway server

test:
	pytest

run:              ## correlate the lab corpus and print the cases
	causeway run

demo:             ## the headline case with every observation and edge
	causeway run -v --top 1

metrics:          ## regenerate results/lab.json (the README table)
	causeway metrics

metrics-ait:      ## the public corpus; needs data/raw/ait_ads.zip
	causeway metrics ait --window 5

serve:            ## console at http://127.0.0.1:8788
	causeway serve

docker:           ## build and run the console in a container
	docker build -t causeway . && docker run --rm -p 8788:8788 causeway

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info

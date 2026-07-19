.PHONY: install test serve demo
install:
	python3 -m pip install -e .
test:
	python3 -m pytest -q
serve:
	screamsiem serve
demo:
	./scripts/demo.sh

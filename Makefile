ifeq ($(OS),Windows_NT)
    ACTIVATE:=.venv/Scripts/activate
else
    ACTIVATE:=.venv/bin/activate
endif

UV:=$(shell uv --version)
ifdef UV
	VENV:=uv venv
	PIP:=uv pip
else
	VENV:=python -m venv
	PIP:=python -m pip
endif

.venv:
	$(VENV) .venv

.PHONY: setup
setup: .venv
	source $(ACTIVATE) && $(PIP) install -Ue .[dev,test]

# Memory: Linux supports ulimit -v (virtual), macOS doesn't.
# Wall-clock: perl alarm(30) works on both platforms.
ifeq ($(shell uname),Linux)
    MEM_LIMIT := ulimit -v 2097152 &&
else
    MEM_LIMIT :=
endif
SAFETY := $(MEM_LIMIT) perl -e 'alarm(30); exec @ARGV or die' --

.PHONY: test
test:
	$(SAFETY) python -m coverage run -m pytest $(TESTOPTS)
	python -m coverage report

.PHONY: format
format:
	ruff format
	ruff check --fix

.PHONY: lint
lint:
	ruff check
	python -m checkdeps --allow-names zap_trace zap_trace
	mypy --strict --install-types --non-interactive zap_trace

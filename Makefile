.DEFAULT_GOAL := help

.PHONY: help generated-check envtest-offline zero-bill

help:
	@python3 ci/run_make_target.py help

generated-check:
	@python3 ci/run_make_target.py generated-check

envtest-offline:
	@python3 ci/run_make_target.py envtest-offline

zero-bill:
	@python3 ci/run_make_target.py zero-bill

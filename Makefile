.PHONY: licenses licenses-check

licenses:
	./scripts/licenses.sh update

licenses-check:
	./scripts/licenses.sh check

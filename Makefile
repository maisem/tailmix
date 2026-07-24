PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
GO ?= go

.PHONY: install licenses licenses-check

install:
	GOBIN="$(DESTDIR)$(BINDIR)" $(GO) install ./cmd/tailmix ./cmd/tailmixd

licenses:
	./scripts/licenses.sh update

licenses-check:
	./scripts/licenses.sh check

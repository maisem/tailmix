PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
GO ?= go
INSTALL ?= install
SED ?= sed
SYSTEMCTL ?= systemctl
SYSTEMD_UNIT_DIR ?= $(PREFIX)/lib/systemd/system
SYSTEMD_UNIT ?= tailmixd.service

.PHONY: check install install-systemd install-test licenses licenses-check

check:
	$(GO) test ./...
	$(GO) vet ./...
	$(GO) tool staticcheck ./...
	$(GO) tool govulncheck ./...
	$(GO) mod tidy -diff
	$(MAKE) licenses-check
	$(MAKE) install-test

install-test:
	./scripts/install_test.sh

install:
	@set -e; \
	version_ldflags="$$($(GO) run ./cmd/mkversion)"; \
	GOBIN="$(DESTDIR)$(BINDIR)" $(GO) install -ldflags "$$version_ldflags" ./cmd/tailmix ./cmd/tailmixd

install-systemd: install
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	$(SED) 's|@BINDIR@|$(BINDIR)|g' systemd/tailmixd.service.in > "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(SYSTEMD_UNIT)"
	chmod 0644 "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(SYSTEMD_UNIT)"
	@set -e; \
	if [ -z "$(DESTDIR)" ]; then \
		$(SYSTEMCTL) daemon-reload; \
		$(SYSTEMCTL) enable "$(SYSTEMD_UNIT)"; \
		$(SYSTEMCTL) restart "$(SYSTEMD_UNIT)"; \
	else \
		echo "Installed $(SYSTEMD_UNIT) under $(DESTDIR); service was not enabled or started."; \
	fi

licenses:
	./scripts/licenses.sh update

licenses-check:
	./scripts/licenses.sh check

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
GO ?= go
PYTHON ?= python3
CI_ARGS ?=
LINUX_NETWORK_ARGS ?=
INSTALL ?= install
SED ?= sed
SYSTEMCTL ?= systemctl
SYSTEMD_UNIT_DIR ?= $(PREFIX)/lib/systemd/system
SYSTEMD_UNIT ?= tailmixd.service

.PHONY: check check-linux-network clean-linux-network check-ci ci install install-systemd install-test licenses licenses-check release-check

check:
	$(GO) test ./...
	$(GO) vet ./...
	$(GO) tool staticcheck ./...
	$(GO) tool govulncheck ./...
	$(GO) mod tidy -diff
	$(MAKE) licenses-check
	$(MAKE) install-test

ci:
	@$(PYTHON) scripts/ci.py $(CI_ARGS)

check-ci:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/ci_test.py

check-linux-network:
	$(GO) test ./cmd/linux-network-e2e
	@set -eu; bin="$$(mktemp "$${TMPDIR:-/tmp}/tailmix-linux-network.XXXXXX")"; \
	trap 'rm -f "$$bin"' EXIT HUP INT TERM; \
	CGO_ENABLED=0 $(GO) build -o "$$bin" ./cmd/linux-network-e2e; \
	GO="$(GO)" "$$bin" $(LINUX_NETWORK_ARGS)

clean-linux-network:
	@$(MAKE) --no-print-directory check-linux-network LINUX_NETWORK_ARGS=--cleanup

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

release-check: check
	$(GO) run github.com/goreleaser/goreleaser/v2@v2.12.7 release --snapshot --clean --parallelism 2

# xKey Android Makefile

.PHONY: help build clean test integration-test install \
	lint android-lint actionlint security trivy-fs ci ci-fast install-tools

.DEFAULT_GOAL := help

DEBUG_APK := app/build/outputs/apk/debug/app-debug.apk
ADB := $(HOME)/Android/Sdk/platform-tools/adb

# CI calls these same targets (handbook devops.md section 4: the Makefile is the
# contract), so a red CI job reproduces locally with the same command.
GRADLEW ?= ./gradlew
TRIVY ?= trivy
TOOLS_BIN ?= $(HOME)/.local/bin

help: ## Show this help
	@echo "xKey Android Build Targets"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Output:"
	@echo "  Debug APK: $(DEBUG_APK)"

build: ## Build debug APK
	$(GRADLEW) assembleDebug
	@echo ""
	@echo "APK: $(DEBUG_APK)"

clean: ## Clean all build artifacts and .class files
	./gradlew clean
	find . -name "*.class" -type f -delete
	rm -rf app/build build .gradle/build-cache

test: ## Run unit tests (JVM, no device)
	$(GRADLEW) testDebugUnitTest
	@echo ""
	@echo "Reports: app/build/reports/tests/testDebugUnitTest/"

lint: android-lint actionlint ## Android lint + actionlint over .github/workflows

android-lint: ## Android lint on the debug variant (abortOnError, see app/build.gradle.kts)
	$(GRADLEW) lintDebug
	@echo ""
	@echo "Report: app/build/reports/lint-results-debug.html"

# actionlint delegates every SC* rule to shellcheck and, when shellcheck is not
# on PATH, silently disables those rules and still exits 0. Refuse to run in
# that state rather than report a gate that checked nothing.
actionlint: ## Lint the workflow files (requires actionlint + shellcheck on PATH)
	@command -v actionlint > /dev/null || { echo "actionlint not found on PATH"; exit 1; }
	@command -v shellcheck > /dev/null || { echo "shellcheck not found on PATH: actionlint would skip every SC rule"; exit 1; }
	actionlint

security: trivy-fs ## Security suite: trivy fs (vuln + secret, CRITICAL/HIGH blocking)

# Version pinned in .trivy-version; install with `make install-tools`.
# Build output and the Gradle cache are skipped: they are generated, not source.
trivy-fs: ## Trivy filesystem scan for dependency CVEs and leaked secrets
	$(TRIVY) fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 \
		--format table --no-progress --ignorefile .trivyignore \
		--skip-dirs build --skip-dirs app/build --skip-dirs .gradle --skip-dirs .kotlin .

install-tools: ## Install the pinned, checksum-verified trivy into $(TOOLS_BIN)
	./scripts/install-trivy.sh $(TOOLS_BIN)

ci-fast: lint build test ## Everything CI runs except the security scan

ci: ci-fast security ## Everything a PR must pass

install: build ## Build and install debug APK via ADB
	$(ADB) install -r $(DEBUG_APK)

integration-test: ## Run instrumented (on-device) tests
	./gradlew connectedDebugAndroidTest
	@echo ""
	@echo "Reports: app/build/reports/androidTests/connected/"

protocol-test: ## Run the wire-protocol integration suite only (in-process pairing server)
	./gradlew connectedDebugAndroidTest \
		-Pandroid.testInstrumentationRunnerArguments.class=com.automatethethings.xkey.e2e.ProtocolIntegrationTest
	@echo ""
	@echo "Reports: app/build/reports/androidTests/connected/"

webauthn-test: ## Run the WebAuthn E2E against the go-xkms relying party
	./scripts/webauthn-backend.sh start
	./scripts/webauthn-backend.sh provider
	./gradlew connectedDebugAndroidTest \
		-Pandroid.testInstrumentationRunnerArguments.class=com.automatethethings.xkey.e2e.WebAuthnE2ETest
	@echo ""
	@echo "Stop the backend with: ./scripts/webauthn-backend.sh stop"

e2e-setup: install ## Configure a connected device/emulator for the go-xkms conformance probe
	./gradlew assembleDebugAndroidTest
	$(ADB) install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
	$(ADB) shell am instrument -w \
		-e class com.automatethethings.xkey.e2e.TcpHsmSettingEnabler \
		com.automatethethings.xkey.debug.test/androidx.test.runner.AndroidJUnitRunner
	$(ADB) forward tcp:8444 tcp:8444
	@echo ""
	@echo "Now launch the app and switch BLE on, then run:"
	@echo "  cd $(HOME)/sources/go-xkms/xkey && go run ./cmd/e2eprobe"
	@echo "Approve the pairing dialog on the device when it appears."

# xKey Android Makefile

.PHONY: help build clean test integration-test install

.DEFAULT_GOAL := help

DEBUG_APK := app/build/outputs/apk/debug/app-debug.apk
ADB := $(HOME)/Android/Sdk/platform-tools/adb

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
	./gradlew assembleDebug
	@echo ""
	@echo "APK: $(DEBUG_APK)"

clean: ## Clean all build artifacts and .class files
	./gradlew clean
	find . -name "*.class" -type f -delete
	rm -rf app/build build .gradle/build-cache

test: ## Run unit tests
	./gradlew testDebugUnitTest
	@echo ""
	@echo "Reports: app/build/reports/tests/testDebugUnitTest/"

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

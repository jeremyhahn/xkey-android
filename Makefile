# xKey Android Makefile

.PHONY: help build clean test integration-test install \
	lint lint-gates android-lint actionlint closing-links-test security trivy-fs ci ci-fast install-tools \
	tools-check tools-check-trivy tools-check-actionlint tools-check-gradle \
	deps-check deps-check-test docker-build docker-build-toolchain docker-build-it \
	docker-run toolchain-image it-image toolchain-image-id it-image-id device-check coverage it-jvm-test \
	reaper-test revert-red-main-test image-lease-test build-image-test

.DEFAULT_GOAL := help

# The one pin file (handbook devcontainer.md section 2), shared with the image.
include scripts/tool-pins.sh

DEBUG_APK := app/build/outputs/apk/debug/app-debug.apk
# adb, first found: ADB=, $ANDROID_HOME, $ANDROID_SDK_ROOT, local.properties
# sdk.dir (escapes such as C\:\\sdk undone), adb on PATH, then the old default.
ADB_DEFAULT := $(HOME)/Android/Sdk/platform-tools/adb
ifeq ($(origin ADB),undefined)
SDK_DIR := $(shell sed -n 's/^[[:space:]]*sdk\.dir[[:space:]]*[=:][[:space:]]*//p' local.properties 2> /dev/null \
	| sed 's/\\\(.\)/\1/g' | tail -n 1)
ADB := $(firstword $(wildcard $(addsuffix /platform-tools/adb,$(ANDROID_HOME) $(ANDROID_SDK_ROOT) $(SDK_DIR))) \
	$(shell command -v adb 2> /dev/null) $(ADB_DEFAULT))
ADB_MISSING := adb not found; looked at $$ANDROID_HOME/platform-tools/adb ($(or $(ANDROID_HOME),unset)), \
	$$ANDROID_SDK_ROOT/platform-tools/adb ($(or $(ANDROID_SDK_ROOT),unset)), \
	local.properties sdk.dir/platform-tools/adb ($(or $(SDK_DIR),unset)), adb on PATH (none), $(ADB_DEFAULT)
else
ADB_MISSING := adb not found at ADB=$(ADB)
endif

# CI calls these same targets (handbook devops.md section 4: the Makefile is the
# contract), so a red CI job reproduces locally with the same command.
GRADLEW ?= ./gradlew
# The devcontainer sets GRADLE_OFFLINE=true: every dependency comes from the
# image's read-only cache, nothing downloads at run time.
GRADLE := $(GRADLEW)$(if $(filter true,$(GRADLE_OFFLINE)), --offline)
TRIVY ?= trivy
TOOLS_BIN ?= $(HOME)/.local/bin

DEVCONTAINER := build/docker/devcontainer
IMAGE_TAG := $(DEVCONTAINER)/image-tag.sh
# The images' names (image-tag.sh, Codex review 6470): trusted, the default
# for a developer's own make and CI's push, schedule or dispatch on main, tags
# <hash>; pr, which ci.yml passes for every other run, tags pr-<hash>, and may
# take the trusted image of the same content (`docker tag`). The namespace is
# a name only and protects nothing (Codex review 6544): a pull request's run
# executes its own Makefile against the daemon main's runs use, so it can
# write any tag, a trusted one included. IMAGE_FRESH is the guard.
IMAGE_NAMESPACE ?= trusted
# CUSTOMIZE (xkey-android): fresh trusted builds (Codex review 6544 on PR
# #40), until trusted runs get a daemon or registry pull requests cannot
# write. IMAGE_FRESH=true, which ci.yml sets on a trusted run, never reuses a
# tag: it builds every image from this checkout's fingerprinted inputs, with
# no build cache (--no-cache: a pull request's builds write the same cache)
# and its base images pulled (--pull) by the digests they are pinned to
# (BASE_IMAGE in scripts/tool-pins.sh, the Dockerfile's syntax line), and the
# build writes the image's ID to IMAGE_ID_DIR/<kind>.iid. `make -s
# toolchain-image-id` and `it-image-id` print the ID a run's stages use, so a
# tag written during the run cannot swap the image under them. A developer's
# make leaves IMAGE_FRESH false and reuses tags as before.
IMAGE_FRESH ?= false
IMAGE_ID_DIR ?= build/image-ids
# Compose interpolates the whole file, so every call sets both image tags,
# whichever service it runs.
COMPOSE := TOOLCHAIN_IMAGE=$$($(IMAGE_TAG) toolchain $(IMAGE_NAMESPACE)) IT_IMAGE=$${IT_IMAGE:-$$($(IMAGE_TAG) it $(IMAGE_NAMESPACE))} \
	docker compose -f $(DEVCONTAINER)/compose.yaml
# APT_PROXY comes from the caller's environment (devcontainer.md section 4).
DOCKER_BUILD := DOCKER_BUILDKIT=1 docker build -f $(DEVCONTAINER)/Dockerfile \
	--build-arg BASE_IMAGE=$(BASE_IMAGE) --build-arg APT_PROXY=$(DEVCACHE_APT_PROXY)

help: ## Show this help
	@echo "xKey Android Build Targets"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Output:"
	@echo "  Debug APK: $(DEBUG_APK)"

build: ## Build debug APK
	$(GRADLE) assembleDebug
	@echo ""
	@echo "APK: $(DEBUG_APK)"

# build/docker/ is tracked source (the devcontainer image), so the root build/
# is emptied around it, never removed. Gradle's clean is app:clean (the root
# project applies no plugin, so has no clean task) and only touches app/build.
clean: ## Clean all build artifacts and .class files
	$(GRADLE) clean
	find . -name "*.class" -type f -delete
	rm -rf app/build .gradle/build-cache
	[ ! -d build ] || find build -mindepth 1 -maxdepth 1 ! -name docker -exec rm -rf {} +

test: ## Run unit tests (JVM, no device)
	$(GRADLE) testDebugUnitTest
	@echo ""
	@echo "Reports: app/build/reports/tests/testDebugUnitTest/"

# The name ci-template's coverage stage calls. No coverage threshold is
# ratified for this app, so none is enforced, and a value is refused rather
# than silently ignored.
coverage: ## Unit tests plus the JaCoCo report (no threshold is enforced)
	@[ -z "$(COVERAGE_THRESHOLD)" ] || { echo "COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD): no coverage threshold is ratified for this app, so none is enforced; leave it empty"; exit 1; }
	$(GRADLE) coverageReport
	@echo ""
	@echo "Report: app/build/reports/jacoco/coverageReport/html/index.html"

lint: android-lint ## Android lint on the debug variant (the repository's own gates run as lint-gates)

# ci-template v1.27: the repository's own gates (scripts, workflows, their
# tests) are not part of lint: CI's lint-gates job runs `make -k lint-gates`
# in parallel with the image job's `make lint`, so nothing runs twice there.
lint-gates: actionlint closing-links-test revert-red-main-test reaper-test image-lease-test build-image-test deps-check-test ## actionlint over .github/workflows + the revert workflow's closing-link and resume fixtures + the reaper's fixtures + the image lease fixtures + the concurrent image build fixtures + deps-check's fixtures (offline)

android-lint: ## Android lint on the debug variant (abortOnError, see app/build.gradle.kts)
	$(GRADLE) lintDebug
	@echo ""
	@echo "Report: app/build/reports/lint-results-debug.html"

# actionlint delegates every SC* rule to shellcheck and, when shellcheck is not
# on PATH, silently disables those rules and still exits 0. Refuse to run in
# that state rather than report a gate that checked nothing.
actionlint: ## Lint the workflow files (requires actionlint + shellcheck on PATH)
	@command -v actionlint > /dev/null || { echo "actionlint not found on PATH"; exit 1; }
	@command -v shellcheck > /dev/null || { echo "shellcheck not found on PATH: actionlint would skip every SC rule"; exit 1; }
	actionlint

closing-links-test: ## Test revert-red-main.yml's closing-link parse against fixtures (bash + jq)
	./scripts/closing-links-test.sh

revert-red-main-test: ## Test that revert-red-main.yml resumes a partial run, against a stubbed Gitea and a local remote (bash + git + jq)
	./scripts/revert-red-main-test.sh

reaper-test: ## Test reap-stale-ci-stacks.sh's image and lease rules against a stubbed docker (bash)
	./scripts/reap-stale-ci-stacks-test.sh

image-lease-test: ## Test ci.yml's image lease steps (rebuild once, export the new ID, fail after the retry, release the lock) against a stubbed docker and make (bash)
	./scripts/image-lease-test.sh

build-image-test: ## Test two concurrent cold builds of one image tag (make docker-build-toolchain, docker-build-it) against a stubbed docker (bash)
	./scripts/build-image-test.sh

security: tools-check-trivy trivy-fs ## Security suite: trivy fs (vuln + secret, CRITICAL/HIGH blocking)

# Version and SHA-256 pinned in scripts/tool-pins.sh; install with `make install-tools`.
# Build output and the Gradle cache are skipped: they are generated, not source.
# build/ is generated except the tracked build/docker/ (the devcontainer image),
# and --skip-dirs cannot skip a directory but one child, so that is a second scan.
TRIVY_FS := $(TRIVY) fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 \
	--format table --no-progress --ignorefile .trivyignore
trivy-fs: ## Trivy filesystem scan for dependency CVEs and leaked secrets
	$(TRIVY_FS) --skip-dirs build --skip-dirs app/build --skip-dirs .gradle --skip-dirs .kotlin .
	$(TRIVY_FS) build/docker

install-tools: ## Install the pinned, checksum-verified trivy into $(TOOLS_BIN)
	./scripts/install-trivy.sh $(TOOLS_BIN)

# The tool check fails closed when a tool is missing or off its pin
# (devcontainer.md section 7).
tools-check: tools-check-trivy tools-check-actionlint tools-check-gradle ## Fail when a pinned tool is missing or off its pin

tools-check-trivy:
	@$(TRIVY) --version 2>/dev/null | grep -qx "Version: $(TRIVY_VERSION)" \
		|| { echo "trivy $(TRIVY_VERSION) not found (scripts/tool-pins.sh); run make install-tools"; exit 1; }

tools-check-actionlint:
	@actionlint -version 2>/dev/null | grep -qx "$(ACTIONLINT_VERSION)" \
		|| { echo "actionlint $(ACTIONLINT_VERSION) not found (scripts/tool-pins.sh)"; exit 1; }

# The wrapper and the image must name the same Gradle, and the Gradle the gates
# run ($(GRADLE): the wrapper on a host, the image's gradle inside it) must be it.
tools-check-gradle:
	@grep -q "gradle-$(GRADLE_VERSION)-bin.zip" gradle/wrapper/gradle-wrapper.properties \
		|| { echo "gradle-wrapper.properties is not on GRADLE_VERSION=$(GRADLE_VERSION) (scripts/tool-pins.sh)"; exit 1; }
	@v=$$($(GRADLE) --version 2>/dev/null | awk '$$1 == "Gradle" { print $$2; exit }'); \
		[ -n "$$v" ] || { echo "$(GRADLE) --version failed: no Gradle to run the gates"; exit 1; }; \
		[ "$$v" = "$(GRADLE_VERSION)" ] || { echo "$(GRADLE) is Gradle $$v, not GRADLE_VERSION=$(GRADLE_VERSION) (scripts/tool-pins.sh)"; exit 1; }

# ci-standard.md section 1: fail on a library behind a release older than 7
# days, report a younger one. The one stage that needs the network: it runs
# Gradle without --offline. Exemptions: scripts/deps-check-exempt.txt.
deps-check: ## Latest-version check: fail on a release older than 7 days (needs the network)
	GRADLEW="$(GRADLEW)" ./scripts/deps-check.sh

deps-check-test: ## Test deps-check's release-age rule against fixtures (offline)
	./scripts/deps-check-test.sh

docker-build: docker-build-toolchain docker-build-it ## Build the toolchain and integration images (skips a tag the daemon holds)

# reuse_or_build <image-tag.sh kind>,<Dockerfile target>: with IMAGE_FRESH=true,
# build $$tag fresh (above) and write its ID to IMAGE_ID_DIR/<kind>.iid. Else
# keep $$tag when the daemon holds it; in the pr namespace, else take the
# trusted image of the same content under $$tag; else build it. Taking an image
# re-tags it, which moves its .Metadata.LastTagTime: the last-used mark
# scripts/reap-stale-ci-stacks.sh ages an image by. CUSTOMIZE (xkey-android):
# the fresh build, and the ci.image.repository label on every build, by which
# the reaper finds this repo's images a later build has untagged (Codex review
# 6544). Every build goes through scripts/build-image.sh, which builds under a
# name of its own and only then points $$tag at the ID the build wrote, so
# concurrent cold builds of one tag all succeed (main run 68429); with
# IMAGE_FRESH=true it keeps that name, which the stages' ID needs.
DOCKER_BUILD_IMAGE = env $(DOCKER_BUILD) --label "ci.image.repository=$${tag%%:*}" --target $(2)
reuse_or_build = if [ "$(IMAGE_FRESH)" = true ]; then \
		case "$(BASE_IMAGE)" in *@sha256:*) ;; *) echo "BASE_IMAGE=$(BASE_IMAGE) is not pinned by digest (scripts/tool-pins.sh)"; exit 1 ;; esac; \
		iid="$(IMAGE_ID_DIR)/$(1).iid"; mkdir -p "$(IMAGE_ID_DIR)" && rm -f "$$iid" \
			&& ./scripts/build-image.sh --keep-name "$$tag" "$$iid" $(DOCKER_BUILD_IMAGE) --pull --no-cache; \
	else \
		{ docker image inspect "$$tag" > /dev/null 2>&1 && docker tag "$$tag" "$$tag"; } \
		|| { [ "$(IMAGE_NAMESPACE)" = pr ] && trusted=$$($(IMAGE_TAG) $(1)) \
			&& docker image inspect "$$trusted" > /dev/null 2>&1 && docker tag "$$trusted" "$$tag"; } \
		|| ./scripts/build-image.sh "$$tag" - $(DOCKER_BUILD_IMAGE); \
	fi

# image_id <image-tag.sh kind>,<tag>: the ID the run's stages use. With
# IMAGE_FRESH=true, the one the fresh build wrote, never a tag lookup; else
# the image the tag names now.
image_id = if [ "$(IMAGE_FRESH)" = true ]; then id=$$(cat "$(IMAGE_ID_DIR)/$(1).iid"); \
		else id=$$(docker image inspect -f '{{.Id}}' "$(2)"); fi || exit; \
	printf '%s\n' "$$id" | grep -Eqx 'sha256:[0-9a-f]{64}' || { echo "$(1) image: '$$id' is not an image ID" >&2; exit 1; }; \
	echo "$$id"

docker-build-toolchain:
	@tag=$$($(IMAGE_TAG) toolchain $(IMAGE_NAMESPACE)) || exit; \
		$(call reuse_or_build,toolchain,toolchain)

docker-build-it:
	@tag=$${IT_IMAGE:-$$($(IMAGE_TAG) it $(IMAGE_NAMESPACE))} || exit; \
		$(call reuse_or_build,it,integration)

docker-run: docker-build-toolchain ## Run CMD in the toolchain image, e.g. make docker-run CMD="make build test"
	@test -n "$(CMD)" || { echo 'usage: make docker-run CMD="make build"'; exit 2; }
	DOCKER_UID=$$(id -u) DOCKER_GID=$$(id -g) \
		$(COMPOSE) run --rm toolchain sh -c '$(CMD)'

toolchain-image: ## Print the toolchain image tag, hashed from its content
	@$(IMAGE_TAG) toolchain $(IMAGE_NAMESPACE)

it-image: ## Print the integration image tag, hashed from its content
	@$(IMAGE_TAG) it $(IMAGE_NAMESPACE)

# CUSTOMIZE (xkey-android): the image IDs CI runs its stages on (Codex review
# 6544), after `make docker-build`.
toolchain-image-id: ## Print the toolchain image's ID (IMAGE_FRESH=true: the one its build wrote)
	@tag=$$($(IMAGE_TAG) toolchain $(IMAGE_NAMESPACE)) || exit; \
		$(call image_id,toolchain,$$tag)

it-image-id: ## Print the integration image's ID (IMAGE_FRESH=true: the one its build wrote)
	@tag=$${IT_IMAGE:-$$($(IMAGE_TAG) it $(IMAGE_NAMESPACE))} || exit; \
		$(call image_id,it,$$tag)

# CI's integration and soak jobs: the instrumented suites need a device, which
# the runners lack, so CI proves the hardened integration image with the JVM
# suite, offline. IT_PROJECT names the compose project CI tears down.
IT_PROJECT ?= xkey-android-it
# CUSTOMIZE (xkey-android): an IT_IMAGE that is an image ID (`make -s
# it-image-id`, as CI passes) is run as it is, with no build and no tag lookup.
# CUSTOMIZE (xkey-android): the suite runs on a copy of the image's /src in the
# /tmp tmpfs. The service's root is read-only, and Gradle 9 refuses a project
# directory it cannot write ("Configuring project ':app' without an existing
# directory is not allowed"); kapt also writes Room's schemas into app/schemas.
# The copy is exactly the image's source, and nothing the image holds is written.
it-jvm-test: $(if $(filter sha256:%,$(IT_IMAGE)),,docker-build-it) ## Run the JVM unit suite in the hardened integration image (no device)
	$(COMPOSE) -p $(IT_PROJECT) run --rm integration \
		sh -c 'cp -R /src /tmp/src && cd /tmp/src && exec make test'

ci-fast: lint lint-gates build test ## Everything CI runs except the security scan

ci: ci-fast security ## Everything a PR must pass

install: device-check build ## Build and install debug APK via ADB
	$(ADB) install -r $(DEBUG_APK)

# The connected suites need a device or emulator over adb; without one they
# stop here rather than deep inside Gradle.
device-check:
	@command -v $(ADB) > /dev/null 2>&1 \
		|| { echo '$(ADB_MISSING): the instrumented suites need adb and a device or emulator'; exit 1; }
	@[ -n "$$($(ADB) devices 2> /dev/null | awk 'NR > 1 && $$2 == "device"')" ] \
		|| { echo "no device or emulator reachable ($(ADB) devices lists none ready): connect one first"; exit 1; }

integration-test: device-check ## Run instrumented (on-device) tests
	$(GRADLE) connectedDebugAndroidTest
	@echo ""
	@echo "Reports: app/build/reports/androidTests/connected/"

protocol-test: device-check ## Run the wire-protocol integration suite only (in-process pairing server)
	$(GRADLE) connectedDebugAndroidTest \
		-Pandroid.testInstrumentationRunnerArguments.class=com.automatethethings.xkey.e2e.ProtocolIntegrationTest
	@echo ""
	@echo "Reports: app/build/reports/androidTests/connected/"

webauthn-test: device-check ## Run the WebAuthn E2E against the go-xkms relying party
	./scripts/webauthn-backend.sh start
	./scripts/webauthn-backend.sh provider
	$(GRADLE) connectedDebugAndroidTest \
		-Pandroid.testInstrumentationRunnerArguments.class=com.automatethethings.xkey.e2e.WebAuthnE2ETest
	@echo ""
	@echo "Stop the backend with: ./scripts/webauthn-backend.sh stop"

e2e-setup: install ## Configure a connected device/emulator for the go-xkms conformance probe
	$(GRADLE) assembleDebugAndroidTest
	$(ADB) install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
	$(ADB) shell am instrument -w \
		-e class com.automatethethings.xkey.e2e.TcpHsmSettingEnabler \
		com.automatethethings.xkey.debug.test/androidx.test.runner.AndroidJUnitRunner
	$(ADB) forward tcp:8444 tcp:8444
	@echo ""
	@echo "Now launch the app and switch BLE on, then run:"
	@echo "  cd $(HOME)/sources/go-xkms/xkey && go run ./cmd/e2eprobe"
	@echo "Approve the pairing dialog on the device when it appears."

# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The syntax line names the BuildKit frontend that parses this file, an image
# like any FROM, so it is pinned by digest too (docker/dockerfile:1's index,
# 2026-10-22; Codex review 6544): a trusted build pulls it (--pull) and runs
# that frontend, never one a pull request tagged on the daemon.
# The project devcontainer, one image for development and CI, in three stages:
# `base` (JDK, Android SDK, Gradle, the read-only dependency cache, a non-root
# user), `toolchain` (base plus the Makefile's tools) and `integration` (base
# plus the source, hardened by compose.yaml). Both finals are FROM base. Every
# version and SHA-256 comes from scripts/tool-pins.sh; the Makefile passes
# BASE_IMAGE from it (`make docker-build`).
#
# Build-time proxy (devcontainer.md section 4): APT_PROXY, from the caller's
# DEVCACHE_APT_PROXY, never a tracked file. Empty means no proxy.

ARG BASE_IMAGE

# ---- fetch: build-only. Downloads and verifies; only /opt leaves it. ----
FROM ${BASE_IMAGE} AS fetch
ARG APT_PROXY=
ARG TARGETARCH
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
# fetch <url> <file> <sha256>: download over https and refuse a mismatch.
RUN cat > /usr/local/bin/fetch <<'EOF'
#!/bin/sh
set -eu
curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
echo "$3  $2" | sha256sum -c -
EOF
RUN chmod 0755 /usr/local/bin/fetch
RUN . /tmp/tool-pins.sh; \
    case "${TARGETARCH}" in \
      amd64) jarch=x64 jsum=${JBR_SHA256_X64} tsum=${TRIVY_SHA256_X64} tarch=64bit asum=${ACTIONLINT_SHA256_X64} ;; \
      arm64) jarch=aarch64 jsum=${JBR_SHA256_AARCH64} tsum=${TRIVY_SHA256_ARM64} tarch=ARM64 asum=${ACTIONLINT_SHA256_ARM64} ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    fetch "https://cache-redirector.jetbrains.com/intellij-jbr/jbrsdk-${JBR_VERSION%-*}-linux-${jarch}-${JBR_VERSION##*-}.tar.gz" jbr.tgz "${jsum}"; \
    mkdir -p /opt/jbr && tar -xzf jbr.tgz -C /opt/jbr --strip-components=1; \
    fetch "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" gradle.zip "${GRADLE_SHA256}"; \
    unzip -q gradle.zip -d /opt && mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle; \
    mkdir -p /opt/tools; \
    fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tarch}.tar.gz" trivy.tgz "${tsum}"; \
    tar -xzf trivy.tgz -C /opt/tools trivy; \
    fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${TARGETARCH}.tar.gz" actionlint.tgz "${asum}"; \
    tar -xzf actionlint.tgz -C /opt/tools actionlint; \
    rm -f ./*.tgz ./*.zip
# The SDK: sdkmanager installs it (package.xml and the layout AGP reads), then
# each installed package is compared file by file with its SHA-256-pinned
# archive, so the bytes in the image are the pinned ones.
ENV JAVA_HOME=/opt/jbr ANDROID_HOME=/opt/android-sdk
RUN . /tmp/tool-pins.sh; \
    cd /tmp; \
    fetch "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip" clt.zip "${CMDLINE_TOOLS_SHA256}"; \
    unzip -q clt.zip -d /tmp/clt; \
    (yes || true) | /tmp/clt/cmdline-tools/bin/sdkmanager --sdk_root="${ANDROID_HOME}" --licenses > /dev/null; \
    /tmp/clt/cmdline-tools/bin/sdkmanager --sdk_root="${ANDROID_HOME}" \
      "platforms;${ANDROID_PLATFORM}" "build-tools;${ANDROID_BUILD_TOOLS}" > /dev/null; \
    check() { fetch "https://dl.google.com/android/repository/$1" pkg.zip "$2"; rm -rf pkg; unzip -q pkg.zip -d pkg; \
      diff -r -x package.xml -x .installer pkg/* "${ANDROID_HOME}/$3"; rm -rf pkg pkg.zip; }; \
    check "${ANDROID_PLATFORM_ARCHIVE}" "${ANDROID_PLATFORM_SHA256}" "platforms/${ANDROID_PLATFORM}"; \
    check "${ANDROID_BUILD_TOOLS_ARCHIVE}" "${ANDROID_BUILD_TOOLS_SHA256}" "build-tools/${ANDROID_BUILD_TOOLS}"; \
    rm -rf /tmp/clt clt.zip "${ANDROID_HOME}/.temp"

# ---- warm: build-only. Fills the Gradle dependency cache by running the
# gates once, then proves it complete; only the cache leaves it, as Gradle's
# read-only cache. Both runs are uid 1000, as at run time, so AGP cannot
# install an SDK package into the root-owned SDK: one off its pin fails here.
#
# It runs nothing the toolchain tag does not hash (image-tag.sh, Codex review
# 6470): the Gradle build files, copied in one by one (keep these COPY lines
# equal to image-tag.sh's list), and a stub app this Dockerfile writes. The
# checkout's sources and tests never enter it, so the tag names everything
# that shapes the image, for the reuse a pull request's run and a developer's
# make do. A trusted run reuses neither a tag nor the build cache (Makefile
# IMAGE_FRESH, Codex review 6544). No RUN takes a --mount=type=cache: BuildKit
# shares such a cache by name, outside any tag and past --no-cache. ----
FROM fetch AS warm
RUN useradd --uid 1000 --create-home --shell /bin/bash builder \
 && install -d -o 1000 -g 1000 /src /opt/gradle-ro-cache
USER 1000
ENV PATH=/opt/gradle/bin:/opt/jbr/bin:${PATH} GRADLE_USER_HOME=/tmp/gradle-home
WORKDIR /src
# The stub: a class and its JUnit test, a manifest, a string and a view-binding
# layout, so every gate task has work and resolves what it resolves for the
# real app: the compile and runtime classpaths, kapt's processors, the unit
# test runtime, AGP's aapt2, lint's jars, and JaCoCo's agent and report jars
# (testDebugUnitTest, lintDebug and coverageReport resolve theirs only by
# running). The build files declare every dependency, the sources none, so the
# real gates need nothing the stub's do not; were one ever to, make lint, build
# or coverage would fail in CI, which runs them offline on this image.
# The directories are made here, as uid 1000, so Gradle can write under them.
RUN mkdir -p gradle/wrapper app/src/main/res/values app/src/main/res/layout \
      app/src/main/kotlin/com/automatethethings/xkey/warm app/src/test/kotlin/com/automatethethings/xkey/warm
COPY --chown=1000:1000 <<EOF app/src/main/AndroidManifest.xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="@string/warm" />
</manifest>
EOF
COPY --chown=1000:1000 <<EOF app/src/main/res/values/strings.xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="warm">warm</string>
</resources>
EOF
COPY --chown=1000:1000 <<EOF app/src/main/res/layout/warm.xml
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent" />
EOF
COPY --chown=1000:1000 <<EOF app/src/main/kotlin/com/automatethethings/xkey/warm/Warm.kt
package com.automatethethings.xkey.warm

object Warm {
    fun sum(a: Int, b: Int): Int = a + b
}
EOF
COPY --chown=1000:1000 <<EOF app/src/test/kotlin/com/automatethethings/xkey/warm/WarmTest.kt
package com.automatethethings.xkey.warm

import org.junit.Assert.assertEquals
import org.junit.Test

class WarmTest {
    @Test
    fun sums() {
        assertEquals(3, Warm.sum(1, 2))
    }
}
EOF
COPY --chown=1000:1000 settings.gradle.kts build.gradle.kts gradle.properties ./
COPY --chown=1000:1000 gradle/libs.versions.toml gradle/gradle-daemon-jvm.properties gradle/
COPY --chown=1000:1000 gradle/wrapper/gradle-wrapper.properties gradle/wrapper/
COPY --chown=1000:1000 app/build.gradle.kts app/
# The gates' tasks, online, download every dependency they use. Any failure
# fails the image build: a dependency that cannot be resolved, or the stub
# failing its own test or lint.
RUN gradle --no-daemon --console=plain assembleDebug testDebugUnitTest coverageReport lintDebug > /tmp/warm.log 2>&1 \
      || { tail -n 60 /tmp/warm.log; exit 1; }; \
    cp -a "${GRADLE_USER_HOME}/caches/modules-2" /opt/gradle-ro-cache/; \
    find /opt/gradle-ro-cache -name '*.lock' -delete; \
    rm -f /opt/gradle-ro-cache/modules-2/gc.properties
# lint's intellij-core jar shades lz4-java 1.11.0 (CVE-2026-106451): its
# classes, no native libraries. No newer lint ships a fixed copy, and a
# shaded copy is not a dependency a constraint can raise, so the classes and
# Maven metadata of the pinned fixed release replace it in the cache, at the
# same entry names (1.11.0 and 1.11.4 have the same file list). A shaded
# copy already at or past the pin is left alone. The proof below runs lint
# on the patched jar.
RUN . /tmp/tool-pins.sh; \
    cd /tmp; \
    fetch "https://repo1.maven.org/maven2/at/yawk/lz4/lz4-java/${LZ4_JAVA_VERSION}/lz4-java-${LZ4_JAVA_VERSION}.jar" lz4.jar "${LZ4_JAVA_SHA256}"; \
    unzip -q lz4.jar 'net/jpountz/*.class' 'META-INF/maven/*' -d lz4; \
    pom=META-INF/maven/at.yawk.lz4/lz4-java/pom.properties; \
    find /opt/gradle-ro-cache -name 'intellij-core-*.jar' -print0 | while IFS= read -r -d '' j; do \
      v=$(unzip -p "$j" "$pom" 2>/dev/null | sed -n 's/^version=//p' || true); \
      [ -n "$v" ] || continue; \
      [ "$(printf '%s\n%s\n' "$v" "${LZ4_JAVA_VERSION}" | sort -V | head -n 1)" != "${LZ4_JAVA_VERSION}" ] || continue; \
      jar uf "$j" -C lz4 .; \
      [ "$(unzip -p "$j" "$pom" | sed -n 's/^version=//p')" = "${LZ4_JAVA_VERSION}" ]; \
      echo "lz4-java ${v} -> ${LZ4_JAVA_VERSION} in ${j##*/}"; \
    done; \
    rm -rf lz4 lz4.jar
# The proof: the same tasks again, --offline, from clean outputs and a fresh
# writable GRADLE_USER_HOME holding only a copy of that cache (no build cache,
# no configuration cache, so every task resolves its dependencies again). A
# dependency the cache lacks fails the image build here, not a gate at run time.
RUN rm -rf build app/build .gradle .kotlin "${GRADLE_USER_HOME}"; \
    mkdir -p /tmp/proof-home/caches; \
    cp -a /opt/gradle-ro-cache/modules-2 /tmp/proof-home/caches/; \
    GRADLE_USER_HOME=/tmp/proof-home gradle --no-daemon --console=plain --offline --no-build-cache \
      assembleDebug testDebugUnitTest coverageReport lintDebug > /tmp/proof.log 2>&1 \
      || { tail -n 60 /tmp/proof.log; exit 1; }; \
    rm -rf /tmp/proof-home build app/build .gradle .kotlin

# ---- base: the toolchain, the dependency cache and a non-root user ----
FROM ${BASE_IMAGE} AS base
ARG APT_PROXY=
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy \
 && useradd --uid 1000 --create-home --shell /bin/bash builder \
 && install -d -o 1000 -g 1000 -m 1777 /gradle-home
# /gradle-home: compose.yaml's GRADLE_USER_HOME volume. An empty named volume
# takes this directory's owner and mode, so the image user owns it and any
# non-root uid (make docker-run runs as the caller's) can write it
# (devcontainer.md section 5).
COPY --from=fetch /opt/jbr /opt/jbr
COPY --from=fetch /opt/gradle /opt/gradle
COPY --from=fetch /opt/android-sdk /opt/android-sdk
COPY --from=warm --chown=0:0 /opt/gradle-ro-cache /opt/gradle-ro-cache
# GRADLE_RO_DEP_CACHE serves every dependency from the image; GRADLE_OFFLINE
# makes the Makefile pass --offline, so nothing downloads at run time
# (devcontainer.md sections 4 and 5). GRADLEW runs the pinned distribution
# directly: the wrapper would download it again into a fresh GRADLE_USER_HOME.
ENV JAVA_HOME=/opt/jbr \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    GRADLE_RO_DEP_CACHE=/opt/gradle-ro-cache \
    GRADLE_OFFLINE=true \
    GRADLEW="gradle --no-daemon --console=plain" \
    PATH=/opt/gradle/bin:/opt/jbr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 1000
WORKDIR /src

# ---- toolchain: base plus every tool the Makefile uses ----
FROM base AS toolchain
ARG APT_PROXY=
USER root
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update && apt-get install -y --no-install-recommends bash curl git jq make shellcheck \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
COPY --from=fetch /opt/tools/trivy /opt/tools/actionlint /usr/local/bin/
USER 1000

# ---- integration: base plus make and the source ----
# The suites run through the Makefile with the image's Gradle, offline.
# TODO(#35): how this stage reaches a device or emulator waits on Software; until then `make integration-test` stops at device-check.
FROM base AS integration
ARG APT_PROXY=
# ci-template v1.29, CUSTOMIZE (xkey-android, Software comment 158438): the
# Debian mirror of devcontainer.md section 6's `ARG APK_INDEX_SUM` and
# `apk upgrade --no-cache`. APT_INDEX_SUM (scripts/apt-index-sum.sh) is the
# package index checksum the image's tag hashes; a new one misses the cache
# from this RUN on, so `apt-get upgrade` takes the fixed packages that base's
# cached upgrade layer does not have. base and toolchain do not declare it.
# APT::Update::Error-Mode=any, as apt-index-sum.sh's probe: an index that
# cannot be refreshed fails the build, so a stale upgrade never caches under
# the new tag (Codex 7845; scripts/image-tag-test.sh checks it).
ARG APT_INDEX_SUM=
USER root
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get -o APT::Update::Error-Mode=any update && apt-get upgrade -y && apt-get install -y --no-install-recommends make \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
USER 1000
COPY --chown=1000:1000 . /src
# A suite run on a host fails saying where it must run.
ENV XKEY_INTEGRATION_IMAGE=1

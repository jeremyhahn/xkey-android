# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The project devcontainer: base, toolchain and integration stages; versions from scripts/tool-pins.sh, APT_PROXY optional.

ARG BASE_IMAGE

# ---- fetch: build-only. Downloads and verifies; only /opt leaves it. ----
FROM ${BASE_IMAGE} AS fetch
ARG APT_PROXY=
ARG TARGETARCH
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
# apt-get retries transient mirror errors (apt-retries.conf, checked by scripts/apt-retry-test.sh).
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80retries
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
# fetch <url> <file> <sha256>: download over https with retries and refuse a
# SHA-256 mismatch; a failed GitHub release download falls back to the API
# asset endpoint (fetch.sh). The checksum is the only trust anchor.
COPY --chmod=0755 build/docker/devcontainer/fetch.sh /usr/local/bin/fetch
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

# ---- warm: fills and proves the Gradle cache from the build files image-tag.sh hashes (keep the COPY lines equal to its list). ----
FROM fetch AS warm
RUN useradd --uid 1000 --create-home --shell /bin/bash builder \
 && install -d -o 1000 -g 1000 /src /opt/gradle-ro-cache
USER 1000
ENV PATH=/opt/gradle/bin:/opt/jbr/bin:${PATH} GRADLE_USER_HOME=/tmp/gradle-home
WORKDIR /src
# The stub app makes every gate task resolve the real app's dependencies; directories made as uid 1000 so Gradle can write.
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
# gradle-quiesce: stop the Gradle daemons and wait for every java process before the cache is copied or deleted (TERM 10 s, KILL 20 s, fail 30 s).
COPY --chmod=0755 <<'EOF' /usr/local/bin/gradle-quiesce
#!/bin/bash
set -euo pipefail
gradle --stop > /dev/null 2>&1 || true
jvms() {
  local c p
  for c in /proc/[0-9]*/comm; do
    read -r p 2>/dev/null < "$c" || continue
    [ "$p" = java ] || continue
    p=${c%/comm}
    echo "${p#/proc/}"
  done
}
for i in $(seq 1 30); do
  pids=$(jvms)
  [ -n "$pids" ] || exit 0
  # shellcheck disable=SC2086 # one pid per word
  [ "$i" -ne 10 ] || kill -TERM $pids 2>/dev/null || true
  # shellcheck disable=SC2086
  [ "$i" -ne 20 ] || kill -KILL $pids 2>/dev/null || true
  sleep 1
done
echo "gradle-quiesce: JVMs outlived the build: $(jvms | tr '\n' ' ')" >&2
exit 1
EOF
# gradle-retry <log> <gradle args...>: retry a dependency download failure or HTTP 429 with doubling waits (GRADLE_RETRY_ATTEMPTS, GRADLE_RETRY_DELAY); any other failure exits.
COPY --chmod=0755 <<'EOF' /usr/local/bin/gradle-retry
#!/bin/bash
set -uo pipefail
log=$1
shift
attempts=${GRADLE_RETRY_ATTEMPTS:-5}
delay=${GRADLE_RETRY_DELAY:-30}
n=1
while :; do
  gradle "$@" > "${log}" 2>&1
  rc=$?
  [ "${rc}" -ne 0 ] || exit 0
  if [ "${n}" -ge "${attempts}" ] || ! grep -Eq 'Could not (resolve|GET|HEAD|download)|status code 429|Too Many Requests' "${log}"; then
    tail -n 60 "${log}"
    echo "gradle-retry: gradle failed (exit ${rc}) on attempt ${n} of ${attempts}" >&2
    exit "${rc}"
  fi
  echo "gradle-retry: attempt ${n} of ${attempts} could not download a dependency; retrying in ${delay} s" >&2
  gradle-quiesce || exit 1
  sleep "${delay}"
  delay=$((delay * 2))
  n=$((n + 1))
done
EOF
COPY --chown=1000:1000 settings.gradle.kts build.gradle.kts gradle.properties ./
COPY --chown=1000:1000 gradle/libs.versions.toml gradle/gradle-daemon-jvm.properties gradle/
COPY --chown=1000:1000 gradle/wrapper/gradle-wrapper.properties gradle/wrapper/
COPY --chown=1000:1000 app/build.gradle.kts app/
# Run the gates online to download every dependency; still unresolved after retries fails the build.
RUN gradle-retry /tmp/warm.log --no-daemon --console=plain -Pkotlin.compiler.execution.strategy=in-process \
      assembleDebug testDebugUnitTest coverageReport lintDebug; \
    gradle-quiesce; \
    cp -a "${GRADLE_USER_HOME}/caches/modules-2" /opt/gradle-ro-cache/; \
    find /opt/gradle-ro-cache -name '*.lock' -delete; \
    rm -f /opt/gradle-ro-cache/modules-2/gc.properties
# Replace lint's shaded lz4-java classes in the cache with the fixed release (CVE-2026-106451); the proof below runs lint on it.
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
# Strip jline-builtins and the remote-telnet/ssh packages from lint's kotlin-compiler jar (unused REPL code with CVEs); the proof below runs lint on it.
RUN cd /tmp; \
    pom=META-INF/maven/org.jline/jline-builtins/pom.properties; \
    find /opt/gradle-ro-cache -name 'kotlin-compiler-*.jar' -print0 | while IFS= read -r -d '' j; do \
      unzip -l "$j" "$pom" > /dev/null 2>&1 || continue; \
      rm -rf kc kc.jar; \
      mkdir kc; \
      unzip -q "$j" -d kc; \
      rm -rf kc/org/jline/builtins kc/org/jline/console kc/org/jline/widget \
        kc/META-INF/maven/org.jline/jline-builtins kc/META-INF/maven/org.jline/jline-remote-telnet \
        kc/META-INF/maven/org.jline/jline-remote-ssh; \
      jar --create --file kc.jar --manifest kc/META-INF/MANIFEST.MF -C kc .; \
      cp kc.jar "$j"; \
      if unzip -l "$j" 'org/jline/builtins/*' 'org/jline/console/*' 'org/jline/widget/*' \
           'META-INF/maven/org.jline/jline-builtins/*' 'META-INF/maven/org.jline/jline-remote-*' > /dev/null 2>&1; then \
        echo "jline REPL packages still in ${j##*/}" >&2; \
        exit 1; \
      fi; \
      echo "jline builtins, console and widget stripped from ${j##*/}"; \
    done; \
    rm -rf kc kc.jar
# The proof: the same tasks offline from a fresh GRADLE_USER_HOME holding only the cache.
RUN rm -rf build app/build .gradle .kotlin "${GRADLE_USER_HOME}"; \
    mkdir -p /tmp/proof-home/caches; \
    cp -a /opt/gradle-ro-cache/modules-2 /tmp/proof-home/caches/; \
    GRADLE_USER_HOME=/tmp/proof-home gradle --no-daemon --console=plain --offline --no-build-cache \
      -Pkotlin.compiler.execution.strategy=in-process \
      assembleDebug testDebugUnitTest coverageReport lintDebug > /tmp/proof.log 2>&1 \
      || { tail -n 60 /tmp/proof.log; exit 1; }; \
    GRADLE_USER_HOME=/tmp/proof-home gradle-quiesce; \
    rm -rf /tmp/proof-home build app/build .gradle .kotlin

# ---- base: the toolchain, the dependency cache and a non-root user ----
FROM ${BASE_IMAGE} AS base
ARG APT_PROXY=
# 80retries (as in fetch): kept in the image, so the apt-get calls of this
# stage and of toolchain and integration (FROM base) all retry transient
# mirror errors.
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80retries
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy \
 && useradd --uid 1000 --create-home --shell /bin/bash builder \
 && install -d -o 1000 -g 1000 -m 1777 /gradle-home
# /gradle-home: compose.yaml's GRADLE_USER_HOME volume, owned by the image user.
COPY --from=fetch /opt/jbr /opt/jbr
COPY --from=fetch /opt/gradle /opt/gradle
COPY --from=fetch /opt/android-sdk /opt/android-sdk
COPY --from=warm --chown=0:0 /opt/gradle-ro-cache /opt/gradle-ro-cache
# Dependencies come from the image cache, offline; GRADLEW runs the pinned distribution directly.
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
 && apt-get update && apt-get install -y --no-install-recommends bash curl git jq make openssh-client shellcheck \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
COPY --from=fetch /opt/tools/trivy /opt/tools/actionlint /usr/local/bin/
USER 1000

# ---- integration: base plus make and the source; suites run offline ----
# TODO(#35): device or emulator access; until then `make integration-test` stops at device-check.
FROM base AS integration
ARG APT_PROXY=
# APT_INDEX_SUM (scripts/apt-index-sum.sh) busts the cache so apt-get upgrade takes fixed packages; a failed index refresh fails the build.
ARG APT_INDEX_SUM=
USER root
RUN if [ -n "${APT_PROXY}" ]; then echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get -o APT::Update::Error-Mode=any update && apt-get upgrade -y && apt-get install -y --no-install-recommends make \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
USER 1000
COPY --chown=1000:1000 . /src
# A suite run on a host fails saying where it must run.
ENV XKEY_INTEGRATION_IMAGE=1

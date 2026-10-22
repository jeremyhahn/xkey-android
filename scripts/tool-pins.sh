# shellcheck shell=sh disable=SC2034  # sourced: every name is read by its caller
# The one pin file (handbook devcontainer.md section 2): every tool version, with a
# SHA-256 for each download. Read by build/docker/devcontainer/Dockerfile (sourced
# in each fetch step), by the Makefile (`include`) and by scripts/install-trivy.sh.
# Plain KEY=value lines only, no quotes or spaces, so make and sh both read it.
# Next versions come from the Company Agent's versions.conf (devops.md section 9)
# and from each upstream named on the line above its pin.

# Debian stable slim, by index digest (docker.io/library/debian:trixie-slim).
# Debian, not alpine (devops.md section 9a): aapt2 and the rest of the Android
# build-tools are glibc-only.
BASE_IMAGE=debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# JetBrains Runtime 21, the vendor and version gradle/gradle-daemon-jvm.properties
# asks for (https://github.com/JetBrains/JetBrainsRuntime/releases).
JBR_VERSION=21.0.11-b1163.116
JBR_SHA256_X64=097bf328b5bf5a236c095b8c8e5204c0eda91e5baa06b37383a7754b10671d8b
JBR_SHA256_AARCH64=21ff925581865d97da97df5c8bdb2ab320dbf6aa609a6556efe3c9a7a7c62db2

# Android command-line tools 23.0 (sdkmanager; build-only stage, never shipped).
# https://dl.google.com/android/repository/repository2-3.xml, cmdline-tools;latest
CMDLINE_TOOLS_BUILD=16111833
CMDLINE_TOOLS_SHA256=0877a1d048fe4a24efe2eff536ca4223f7adeb58648bb81909d33c446918cfa8

# SDK packages: compileSdk 34 (app/build.gradle.kts) and AGP 9.0's default
# build-tools. sdkmanager installs them; the build-only stage checks the result
# against these archives.
ANDROID_PLATFORM=android-34
ANDROID_PLATFORM_ARCHIVE=platform-34-ext7_r03.zip
ANDROID_PLATFORM_SHA256=16fdb74c55e59ae3ef52def135aec713508467bd56d7dabcd8c9be31fa8b20f3
ANDROID_BUILD_TOOLS=36.0.0
ANDROID_BUILD_TOOLS_ARCHIVE=build-tools_r36_linux.zip
ANDROID_BUILD_TOOLS_SHA256=5d9ac77fb6ff43d9da518a337b4fcf8f9097113df531d99ccefe80ef7ce8250b

# Gradle: the distribution gradle/wrapper/gradle-wrapper.properties names
# (https://services.gradle.org/distributions/gradle-9.1.0-bin.zip.sha256).
GRADLE_VERSION=9.1.0
GRADLE_SHA256=a17ddd85a26b6a7f5ddb71ff8b05fc5104c0202c6e64782429790c933686c806

# trivy (https://github.com/aquasecurity/trivy/releases, trivy_<v>_checksums.txt).
TRIVY_VERSION=0.74.0
TRIVY_SHA256_X64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5

# gradle-versions-plugin, `make deps-check` only, applied by an init script
# (https://plugins.gradle.org/m2/com/github/ben-manes/gradle-versions-plugin/).
DEPS_CHECK_PLUGIN_VERSION=0.54.0
DEPS_CHECK_PLUGIN_SHA256=1b02b5e7fab2dc052ae2f94753ee6db1ecda42813f7571b2729a9445b44ea5d5

# actionlint (https://github.com/rhysd/actionlint/releases, checksums.txt).
ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256_X64=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ACTIONLINT_SHA256_ARM64=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6

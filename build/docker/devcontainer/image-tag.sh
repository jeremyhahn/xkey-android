#!/bin/sh
# Prints a devcontainer image tag from the content hash of its inputs. Usage: image-tag.sh toolchain|it [trusted|pr]
# toolchain hashes the Dockerfile, fetch.sh, the pins and the Gradle build files; it hashes the tree plus APK_INDEX_SUM/APT_INDEX_SUM.
set -eu

cd "$(dirname -- "$0")/../../.."
REPO=xkey-android

case "${2:-trusted}" in
	trusted) ns= ;;
	pr) ns=pr- ;;
	*)
		echo "$0: namespace '$2' is neither trusted nor pr" >&2
		exit 2
		;;
esac

case "${1:-}" in
	toolchain)
		hash=$(cat build/docker/devcontainer/Dockerfile build/docker/devcontainer/fetch.sh \
			build/docker/devcontainer/apt-retries.conf scripts/tool-pins.sh \
			gradle/libs.versions.toml gradle/wrapper/gradle-wrapper.properties \
			gradle/gradle-daemon-jvm.properties gradle.properties \
			settings.gradle.kts build.gradle.kts app/build.gradle.kts |
			sha256sum | cut -c1-16)
		echo "${REPO}-toolchain:${ns}${hash}"
		;;
	it)
		hash=$({
			git rev-parse 'HEAD^{tree}'
			git diff HEAD --binary
			git ls-files --others --exclude-standard -z | xargs -0r sha256sum
			if [ -n "${APK_INDEX_SUM:-}" ]; then
				printf 'APK_INDEX_SUM=%s\n' "$APK_INDEX_SUM"
			fi
			if [ -n "${APT_INDEX_SUM:-}" ]; then
				printf 'APT_INDEX_SUM=%s\n' "$APT_INDEX_SUM"
			fi
		} | sha256sum | cut -c1-16)
		echo "${REPO}-ci-it:${ns}${hash}"
		;;
	*)
		echo "usage: $0 toolchain|it [trusted|pr]" >&2
		exit 2
		;;
esac

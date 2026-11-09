#!/bin/sh
# Prints a devcontainer image tag named by the content hash of the files that
# build the image, for `make toolchain-image` and `make it-image`.
#
#   usage: image-tag.sh toolchain|it [trusted|pr]
#
# toolchain: the Dockerfile, its fetch.sh, the pin file and the Gradle build files, the
#            analogue of a Go module's go.mod and go.sum. They are every file
#            the image is built from: the Dockerfile's warm stage copies in
#            these and no other (keep its COPY lines equal to this list) and
#            runs the gates on a stub app the Dockerfile writes itself, never
#            on the checkout's sources or tests. A build script is code too:
#            one a pull request changes is hashed, so it names another image.
# it:        the whole build context: the commit's tree, and on a dirty
#            checkout the diff and every untracked file .gitignore keeps.
#            Also APK_INDEX_SUM, the Alpine package
#            index checksum (scripts/apk-index-sum.sh) CI passes; `none` here,
#            whose base is Debian. CUSTOMIZE (xkey-android): also
#            APT_INDEX_SUM, the Debian package index checksum
#            (scripts/apt-index-sum.sh). Each sum, unset or empty, leaves the
#            tag alone; both unset, the tag is the tree's alone.
#            scripts/image-tag-test.sh (make lint-gates) checks this.
#
# The namespace is the run's class, as a name. trusted,
# the default, is a developer's own make and CI's push or dispatch
# on main; ci.yml passes pr for every other run, from the event, and a pr tag
# is pr-<hash>. It protects nothing: a pull request's run
# can write any tag on a daemon it shares with main, so a trusted run never
# looks a tag up. It builds fresh and runs by image ID (Makefile IMAGE_FRESH).
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
		hash=$(cat build/docker/devcontainer/Dockerfile build/docker/devcontainer/fetch.sh scripts/tool-pins.sh \
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

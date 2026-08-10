# Suggested Commands

## Build
- `make build` - Build debug APK
- `make build-release` - Build release APK (or `./gradlew assembleRelease`)
- `make install` - Build + install debug APK via ADB
- `make install-release` - Build + install release APK via ADB

## Testing
- `make test` - Unit tests (`./gradlew testDebugUnitTest`)
- `make integration-test` - Instrumented on-device tests (`./gradlew connectedDebugAndroidTest`)

## Code Quality
- `make lint` - Lint checks
- `./gradlew ktlintCheck` - Kotlin lint (if configured)

## Other
- `make clean` - Clean build artifacts
- `make shell` - Interactive shell in Docker build container
- `make help` - Show all targets

## Reports
- Unit test reports: `app/build/reports/tests/testDebugUnitTest/`
- Instrumented test reports: `app/build/reports/androidTests/connected/`
- APK output: `app/build/outputs/apk/debug/app-debug.apk`

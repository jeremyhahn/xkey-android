# Android build environment for Passkey
FROM eclipse-temurin:17-jdk-jammy

# Set environment variables
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=${ANDROID_HOME}
ENV PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Download and install Android command-line tools
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    curl -o /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip && \
    unzip /tmp/cmdline-tools.zip -d ${ANDROID_HOME}/cmdline-tools && \
    mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

# Accept licenses and install SDK components
RUN yes | sdkmanager --licenses && \
    sdkmanager \
    "platform-tools" \
    "platforms;android-34" \
    "build-tools;34.0.0"

# Create non-root user for builds
RUN useradd -m -s /bin/bash builder
RUN chown -R builder:builder ${ANDROID_HOME}

# Set working directory
WORKDIR /app

# Copy project files
COPY --chown=builder:builder . .

# Create gradle cache directory with correct permissions
RUN mkdir -p /app/.gradle && chown -R builder:builder /app

# Switch to non-root user
USER builder

# Set Gradle user home to writable location
ENV GRADLE_USER_HOME=/home/builder/.gradle

# Generate Gradle wrapper if not present
RUN if [ ! -f gradle/wrapper/gradle-wrapper.jar ]; then \
    curl -L -o /tmp/gradle.zip https://services.gradle.org/distributions/gradle-8.7-bin.zip && \
    unzip -q /tmp/gradle.zip -d /tmp && \
    /tmp/gradle-8.7/bin/gradle wrapper --gradle-version 8.7 --no-daemon && \
    rm -rf /tmp/gradle* ; \
    fi

# Default command: build debug APK
CMD ["./gradlew", "assembleDebug", "--no-daemon"]

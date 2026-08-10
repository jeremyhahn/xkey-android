/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.automatethethings.xkey.audit.AuditLogger
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * User verification policy for FIDO2/WebAuthn operations.
 *
 * This enum defines whether user verification (typically biometric authentication)
 * is required for passkey operations, aligning with the FIDO2 specification's
 * userVerification options.
 */
public enum class UserVerificationPolicy {
    /**
     * User verification is disabled.
     *
     * Operations will proceed without requiring biometric authentication.
     * This mode is less secure and should only be used in low-risk scenarios
     * or when the device lacks biometric capabilities.
     */
    DISABLED,

    /**
     * User verification is required for all operations.
     *
     * Every xKey operation will require successful biometric authentication
     * before proceeding. This is the recommended setting for maximum security
     * and FIDO2 compliance.
     */
    REQUIRED
}

/**
 * Authentication mode that determines when biometric verification is required.
 *
 * This enum controls the frequency and timing of biometric prompts,
 * balancing security with user experience.
 */
public enum class BiometricAuthMode {
    /**
     * Require biometric authentication for every cryptographic operation.
     *
     * This is the most secure mode, ensuring explicit user consent for
     * each signing or decryption operation. Recommended for high-security
     * environments.
     */
    PER_OPERATION,

    /**
     * Require biometric authentication once per time window.
     *
     * After successful authentication, subsequent operations within the
     * configured time window proceed without additional biometric prompts.
     * The window duration is configured via [BiometricSettingsData.timeWindowSeconds].
     */
    TIME_WINDOW,

    /**
     * Require biometric authentication once per session.
     *
     * Authentication is required when the app starts or resumes from background.
     * Subsequent operations proceed without additional prompts until the
     * session ends (app is closed or moved to background).
     */
    PER_SESSION
}

/**
 * Policy for biometric authentication during key attestation operations.
 *
 * This enum controls when biometric verification is required before proving
 * key existence to remote parties via attestation.
 */
public enum class AttestationBiometricPolicy {
    /**
     * Always require biometric verification for attestation requests.
     *
     * Maximum security - proves user is present when proving key existence.
     * This is the recommended setting for high-security environments.
     */
    ALWAYS,

    /**
     * Skip biometric for paired/known devices, require for unknown.
     *
     * Balanced approach - trusted devices that have been previously paired
     * get a streamlined experience, while unknown devices still require
     * explicit user verification.
     */
    PAIRED_DEVICES_SKIP,

    /**
     * Never require biometric for attestation requests.
     *
     * Convenience mode - attestation only proves key exists, not user presence.
     * Use this only in low-security environments or when attestation is
     * performed frequently by trusted automation.
     */
    NEVER
}

/**
 * Pre-defined time window durations for [BiometricAuthMode.TIME_WINDOW] mode.
 *
 * Each value represents the number of seconds that authentication remains valid
 * after a successful biometric verification.
 *
 * @property seconds The duration in seconds.
 */
public enum class AuthTimeWindow(public val seconds: Int) {
    /**
     * 30-second authentication window.
     *
     * Shortest duration, suitable for high-security scenarios requiring
     * frequent re-authentication.
     */
    SECONDS_30(30),

    /**
     * 1-minute authentication window.
     *
     * Balanced option for moderate security with reasonable convenience.
     */
    MINUTES_1(60),

    /**
     * 2-minute authentication window.
     *
     * Default option providing good balance between security and usability
     * for typical passkey operations.
     */
    MINUTES_2(120),

    /**
     * 5-minute authentication window.
     *
     * Extended duration suitable for batch operations or workflows
     * requiring multiple authentications in sequence.
     */
    MINUTES_5(300),

    /**
     * 10-minute authentication window.
     *
     * Longest pre-defined duration, suitable for extended work sessions
     * where frequent prompts would be disruptive.
     */
    MINUTES_10(600);

    public companion object {
        /**
         * Find the [AuthTimeWindow] matching the given seconds value.
         *
         * @param seconds The duration in seconds to match.
         * @return The matching [AuthTimeWindow], or null if no match found.
         */
        public fun fromSeconds(seconds: Int): AuthTimeWindow? =
            entries.find { it.seconds == seconds }

        /**
         * Find the [AuthTimeWindow] matching the given seconds value,
         * returning a default if no match found.
         *
         * @param seconds The duration in seconds to match.
         * @param default The default value if no match found.
         * @return The matching [AuthTimeWindow], or [default] if no match found.
         */
        public fun fromSecondsOrDefault(
            seconds: Int,
            default: AuthTimeWindow = MINUTES_2
        ): AuthTimeWindow = fromSeconds(seconds) ?: default
    }
}

/**
 * Data class containing biometric authentication settings.
 *
 * This immutable data class encapsulates all biometric-related configuration
 * for the xKey application, including verification policy, authentication
 * mode, and time window settings.
 *
 * Usage:
 * ```kotlin
 * val settings = BiometricSettingsData(
 *     uvPolicy = UserVerificationPolicy.REQUIRED,
 *     authMode = BiometricAuthMode.TIME_WINDOW,
 *     timeWindowSeconds = AuthTimeWindow.MINUTES_5.seconds
 * )
 *
 * if (settings.isBiometricEnabled) {
 *     // Perform biometric authentication
 * }
 * ```
 *
 * @property uvPolicy The user verification policy determining if biometric is required.
 * @property authMode The authentication mode controlling prompt frequency.
 * @property timeWindowSeconds The time window duration in seconds for [BiometricAuthMode.TIME_WINDOW] mode.
 */
public data class BiometricSettingsData(
    val uvPolicy: UserVerificationPolicy = UserVerificationPolicy.REQUIRED,
    val authMode: BiometricAuthMode = BiometricAuthMode.PER_OPERATION,
    val timeWindowSeconds: Int = AuthTimeWindow.MINUTES_2.seconds,
    val attestationBiometricPolicy: AttestationBiometricPolicy = AttestationBiometricPolicy.ALWAYS,
    /**
     * Enforce WebAuthn user-verification semantics exactly (default, and the
     * industry-standard behavior).
     *
     * When true, a ceremony whose relying party sets
     * `userVerification: "required"` fails if this device cannot actually
     * verify the user, rather than completing without verification. The `UV`
     * bit in authenticator data always reflects whether verification really
     * happened, in both modes — that flag is what a relying party trusts, so
     * it is never asserted falsely.
     *
     * Setting this to false only relaxes the *refusal*: such ceremonies are
     * allowed to proceed, still reporting `UV=0` honestly. Compliant relying
     * parties will reject those assertions, which is the correct outcome; the
     * option exists for local testing and for lenient internal deployments.
     */
    val strictUserVerification: Boolean = true
) {
    /**
     * Indicates whether biometric authentication is enabled.
     *
     * Returns `true` if [uvPolicy] is [UserVerificationPolicy.REQUIRED],
     * meaning biometric verification will be performed for passkey operations.
     */
    val isBiometricEnabled: Boolean
        get() = uvPolicy == UserVerificationPolicy.REQUIRED

    /**
     * Get the [AuthTimeWindow] enum value matching [timeWindowSeconds].
     *
     * @return The matching [AuthTimeWindow], or null if the current value
     *         doesn't match any pre-defined window.
     */
    public fun getAuthTimeWindow(): AuthTimeWindow? =
        AuthTimeWindow.fromSeconds(timeWindowSeconds)

    /**
     * Create a copy with a different time window from the [AuthTimeWindow] enum.
     *
     * @param timeWindow The new time window to use.
     * @return A new [BiometricSettingsData] with the updated time window.
     */
    public fun withTimeWindow(timeWindow: AuthTimeWindow): BiometricSettingsData =
        copy(timeWindowSeconds = timeWindow.seconds)

    public companion object {
        /**
         * Default settings with biometric required and per-operation authentication.
         */
        public val DEFAULT: BiometricSettingsData = BiometricSettingsData()

        /**
         * Settings with biometric disabled.
         */
        public val DISABLED: BiometricSettingsData = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.DISABLED
        )

        /**
         * High-security settings with per-operation authentication.
         */
        public val HIGH_SECURITY: BiometricSettingsData = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.REQUIRED,
            authMode = BiometricAuthMode.PER_OPERATION,
            timeWindowSeconds = AuthTimeWindow.SECONDS_30.seconds
        )

        /**
         * Convenience settings with session-based authentication.
         */
        public val CONVENIENCE: BiometricSettingsData = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.REQUIRED,
            authMode = BiometricAuthMode.PER_SESSION,
            timeWindowSeconds = AuthTimeWindow.MINUTES_10.seconds
        )
    }
}

/**
 * Extension property to create a DataStore instance for biometric settings.
 */
private val Context.biometricSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "biometric_settings"
)

/**
 * Repository for persisting and retrieving biometric authentication settings.
 *
 * This class provides a coroutine-based API for managing biometric settings
 * using Jetpack DataStore for persistence. Settings are stored as preferences
 * and automatically persisted to disk.
 *
 * Usage:
 * ```kotlin
 * val repository = BiometricSettingsRepository(context)
 *
 * // Observe settings changes
 * repository.settingsFlow.collect { settings ->
 *     updateUI(settings)
 * }
 *
 * // Update settings
 * repository.updateSettings(
 *     BiometricSettingsData(
 *         uvPolicy = UserVerificationPolicy.REQUIRED,
 *         authMode = BiometricAuthMode.TIME_WINDOW,
 *         timeWindowSeconds = AuthTimeWindow.MINUTES_5.seconds
 *     )
 * )
 * ```
 *
 * @param context The Android context used to access DataStore.
 */
public class BiometricSettingsRepository(
    private val context: Context
) {
    private val dataStore: DataStore<Preferences> = context.biometricSettingsDataStore

    /**
     * Flow of biometric settings that emits whenever settings change.
     *
     * Collectors will receive the current settings immediately upon subscription
     * and subsequent updates as they occur.
     */
    public val settingsFlow: Flow<BiometricSettingsData> = dataStore.data.map { preferences ->
        mapPreferencesToSettings(preferences)
    }

    /**
     * Get the current biometric settings synchronously.
     *
     * This is a suspend function that retrieves the current settings
     * without setting up a continuous flow.
     *
     * @return The current [BiometricSettingsData].
     */
    public suspend fun getSettings(): BiometricSettingsData {
        return settingsFlow.first()
    }

    /**
     * Update all biometric settings at once.
     *
     * @param settings The new settings to persist.
     */
    public suspend fun updateSettings(settings: BiometricSettingsData) {
        dataStore.edit { preferences ->
            preferences[KEY_UV_POLICY] = settings.uvPolicy.name
            preferences[KEY_AUTH_MODE] = settings.authMode.name
            preferences[KEY_TIME_WINDOW_SECONDS] = settings.timeWindowSeconds
            preferences[KEY_ATTESTATION_BIOMETRIC_POLICY] = settings.attestationBiometricPolicy.name
            preferences[KEY_STRICT_USER_VERIFICATION] = settings.strictUserVerification
        }
    }

    /**
     * Update the user verification policy.
     *
     * @param policy The new user verification policy.
     */
    public suspend fun updateUserVerificationPolicy(policy: UserVerificationPolicy) {
        val oldValue = getSettings().uvPolicy.name
        dataStore.edit { preferences ->
            preferences[KEY_UV_POLICY] = policy.name
        }
        AuditLogger.logSettingsChanged(
            settingName = "userVerificationPolicy",
            oldValue = oldValue,
            newValue = policy.name
        )
    }

    /**
     * Update the biometric authentication mode.
     *
     * @param mode The new authentication mode.
     */
    public suspend fun updateAuthMode(mode: BiometricAuthMode) {
        val oldValue = getSettings().authMode.name
        dataStore.edit { preferences ->
            preferences[KEY_AUTH_MODE] = mode.name
        }
        AuditLogger.logSettingsChanged(
            settingName = "authMode",
            oldValue = oldValue,
            newValue = mode.name
        )
    }

    /**
     * Update the time window duration for [BiometricAuthMode.TIME_WINDOW] mode.
     *
     * @param seconds The time window duration in seconds.
     */
    public suspend fun updateTimeWindow(seconds: Int) {
        require(seconds > 0) { "Time window must be positive" }
        dataStore.edit { preferences ->
            preferences[KEY_TIME_WINDOW_SECONDS] = seconds
        }
    }

    /**
     * Update the time window duration using a pre-defined [AuthTimeWindow].
     *
     * @param timeWindow The time window enum value.
     */
    public suspend fun updateTimeWindow(timeWindow: AuthTimeWindow) {
        updateTimeWindow(timeWindow.seconds)
    }

    /**
     * Update the biometric policy for attestation operations.
     *
     * @param policy The new attestation biometric policy.
     */
    public suspend fun updateAttestationBiometricPolicy(policy: AttestationBiometricPolicy) {
        val oldValue = getSettings().attestationBiometricPolicy.name
        dataStore.edit { preferences ->
            preferences[KEY_ATTESTATION_BIOMETRIC_POLICY] = policy.name
        }
        AuditLogger.logSettingsChanged(
            settingName = "attestationBiometricPolicy",
            oldValue = oldValue,
            newValue = policy.name
        )
    }

    /**
     * Enable or disable biometric authentication.
     *
     * This is a convenience method that sets [UserVerificationPolicy.REQUIRED]
     * when enabled or [UserVerificationPolicy.DISABLED] when disabled.
     *
     * @param enabled True to enable biometric authentication, false to disable.
     */
    public suspend fun setBiometricEnabled(enabled: Boolean) {
        val policy = if (enabled) {
            UserVerificationPolicy.REQUIRED
        } else {
            UserVerificationPolicy.DISABLED
        }
        updateUserVerificationPolicy(policy)
    }

    /**
     * Reset all settings to their default values.
     */
    public suspend fun resetToDefaults() {
        updateSettings(BiometricSettingsData.DEFAULT)
    }

    /**
     * Clear all stored settings.
     *
     * After calling this method, [settingsFlow] will emit default values
     * until new settings are saved.
     */
    public suspend fun clearSettings() {
        dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    /**
     * Map DataStore preferences to [BiometricSettingsData].
     */
    private fun mapPreferencesToSettings(preferences: Preferences): BiometricSettingsData {
        val uvPolicyName = preferences[KEY_UV_POLICY]
        val authModeName = preferences[KEY_AUTH_MODE]
        val timeWindowSeconds = preferences[KEY_TIME_WINDOW_SECONDS]
        val attestationBiometricPolicyName = preferences[KEY_ATTESTATION_BIOMETRIC_POLICY]
        val strictUserVerification = preferences[KEY_STRICT_USER_VERIFICATION]

        return BiometricSettingsData(
            uvPolicy = uvPolicyName?.let { name ->
                runCatching { UserVerificationPolicy.valueOf(name) }.getOrNull()
            } ?: UserVerificationPolicy.REQUIRED,
            authMode = authModeName?.let { name ->
                runCatching { BiometricAuthMode.valueOf(name) }.getOrNull()
            } ?: BiometricAuthMode.PER_OPERATION,
            timeWindowSeconds = timeWindowSeconds ?: AuthTimeWindow.MINUTES_2.seconds,
            attestationBiometricPolicy = attestationBiometricPolicyName?.let { name ->
                runCatching { AttestationBiometricPolicy.valueOf(name) }.getOrNull()
            } ?: AttestationBiometricPolicy.ALWAYS,
            // Absent preference means compliant: WebAuthn conformance is the default.
            strictUserVerification = strictUserVerification ?: true
        )
    }

    private companion object {
        val KEY_UV_POLICY = stringPreferencesKey("uv_policy")
        val KEY_AUTH_MODE = stringPreferencesKey("auth_mode")
        val KEY_TIME_WINDOW_SECONDS = intPreferencesKey("time_window_seconds")
        val KEY_ATTESTATION_BIOMETRIC_POLICY = stringPreferencesKey("attestation_biometric_policy")
        val KEY_STRICT_USER_VERIFICATION = booleanPreferencesKey("strict_user_verification")
    }
}

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
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.net.URI

/**
 * Bootstrap method identifier for CA bundle retrieval.
 *
 * These methods correspond to the go-xkms bootstrap package's Method type
 * and define how the Android client retrieves the CA bundle from a keychain server.
 *
 * Methods are ordered by security strength:
 * - DANE: Strongest verification using DNS-based authentication with DNSSEC
 * - NOISE: Encrypted channel using pre-shared Curve25519 key
 * - SPKI: TLS with SPKI pin verification
 * - DIRECT: Standard HTTPS using system trust store (fallback)
 *
 * @property displayName Human-readable name for UI display.
 * @property description Detailed description of the bootstrap method.
 */
public enum class BootstrapMethod(
    public val displayName: String,
    public val description: String
) {
    /**
     * DANE (DNS-based Authentication of Named Entities).
     *
     * Uses TLSA DNS records with DNSSEC validation to verify the server's
     * CA bundle. This is the strongest verification method as it relies
     * on cryptographically authenticated DNS records.
     */
    DANE(
        displayName = "DANE (DNS-based)",
        description = "Uses TLSA DNS records with DNSSEC validation for strongest verification"
    ),

    /**
     * Noise Protocol (Noise_NK pattern).
     *
     * Establishes an encrypted channel using a pre-shared server static
     * public key (Curve25519). The 32-byte key must be distributed
     * out-of-band (QR code, provisioning config, etc.).
     */
    NOISE(
        displayName = "Noise Protocol",
        description = "Encrypted channel using pre-shared Curve25519 server key"
    ),

    /**
     * SPKI Pinning (Subject Public Key Info).
     *
     * Uses TLS with SPKI pin verification. The server's public key hash
     * (SHA-256) must be distributed out-of-band for trust-on-first-use.
     */
    SPKI(
        displayName = "SPKI Pinning",
        description = "TLS with certificate public key pin verification"
    ),

    /**
     * Direct HTTPS.
     *
     * Standard HTTPS using the Android system trust store. This is the
     * least secure option and serves as a last-resort fallback when
     * no other method is available.
     */
    DIRECT(
        displayName = "Direct HTTPS",
        description = "Standard HTTPS using system trust store (fallback)"
    );

    public companion object {
        /**
         * Default method order matching go-xkms's DefaultMethodOrder.
         *
         * Methods are tried in order of security strength: DANE (strongest),
         * Noise (pre-shared key), SPKI (pinned TLS), Direct (system trust).
         */
        public val DEFAULT_ORDER: List<BootstrapMethod> = listOf(DANE, NOISE, SPKI, DIRECT)

        /**
         * Parse a method from its name string.
         *
         * @param name The method name (case-insensitive).
         * @return The matching [BootstrapMethod], or null if not found.
         */
        public fun fromName(name: String): BootstrapMethod? =
            entries.find { it.name.equals(name, ignoreCase = true) }

        /**
         * Parse a list of methods from a comma-separated string.
         *
         * @param methodsStr Comma-separated method names.
         * @return List of parsed methods, skipping any invalid names.
         */
        public fun fromCommaSeparated(methodsStr: String): List<BootstrapMethod> {
            if (methodsStr.isBlank()) return DEFAULT_ORDER
            return methodsStr.split(",")
                .mapNotNull { fromName(it.trim()) }
                .ifEmpty { DEFAULT_ORDER }
        }
    }
}

/**
 * Pre-defined timeout durations for bootstrap operations.
 *
 * @property seconds The timeout duration in seconds.
 */
public enum class BootstrapTimeout(public val seconds: Int) {
    SECONDS_10(10),
    SECONDS_15(15),
    SECONDS_30(30),
    SECONDS_60(60);

    public companion object {
        public fun fromSeconds(seconds: Int): BootstrapTimeout? =
            entries.find { it.seconds == seconds }

        public fun fromSecondsOrDefault(
            seconds: Int,
            default: BootstrapTimeout = SECONDS_15
        ): BootstrapTimeout = fromSeconds(seconds) ?: default
    }
}

/**
 * DANE bootstrap configuration.
 *
 * @property serverUrl Base URL for DANE bootstrap (e.g., "https://kms.example.com:8443").
 * @property dnsServer DNS resolver address (e.g., "8.8.8.8:53").
 * @property dnsOverTls Enable DNS-over-TLS (DoT) on port 853.
 * @property requireDnssec Require DNSSEC validation for DANE.
 */
public data class DANEConfig(
    val serverUrl: String,
    val dnsServer: String = "8.8.8.8:53",
    val dnsOverTls: Boolean = false,
    val requireDnssec: Boolean = true
)

/**
 * Noise protocol bootstrap configuration.
 *
 * @property serverAddress Noise server address in host:port format.
 * @property serverStaticKey Hex-encoded 32-byte Curve25519 server public key.
 */
public data class NoiseConfig(
    val serverAddress: String,
    val serverStaticKey: String
)

/**
 * SPKI pinning bootstrap configuration.
 *
 * @property serverUrl Base URL for SPKI-pinned bootstrap.
 * @property spkiPinSha256 Hex-encoded SHA-256 hash of server's SPKI.
 */
public data class SPKIConfig(
    val serverUrl: String,
    val spkiPinSha256: String
)

/**
 * Direct HTTPS bootstrap configuration.
 *
 * @property serverUrl Base URL for direct HTTPS bootstrap.
 */
public data class DirectConfig(
    val serverUrl: String
)

/**
 * Data class containing bootstrap settings for CA bundle retrieval.
 *
 * These settings control how the xKey Android client bootstraps trust
 * with a go-xkms server by retrieving its CA bundle. Multiple
 * bootstrap methods can be configured, and they are tried in priority
 * order until one succeeds.
 *
 * Usage:
 * ```kotlin
 * val settings = BootstrapSettingsData(
 *     autoBootstrapEnabled = true,
 *     methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT),
 *     noiseEnabled = true,
 *     noiseServerAddr = "kms.example.com:8445",
 *     noiseServerStaticKey = "ab12cd34..." // 64 hex chars
 * )
 *
 * if (settings.isMethodEnabled(BootstrapMethod.NOISE)) {
 *     // Configure Noise bootstrapper
 * }
 * ```
 *
 * @property autoBootstrapEnabled Master switch for automatic bootstrap on connection.
 * @property methodOrder Priority order for trying bootstrap methods.
 * @property perMethodTimeoutSeconds Timeout for each individual method attempt.
 * @property daneEnabled Whether DANE/TLSA bootstrap is enabled.
 * @property daneServerUrl Base URL for DANE bootstrap (e.g., "https://kms.example.com:8443").
 * @property daneDnsServer DNS resolver address (e.g., "8.8.8.8:53").
 * @property daneDnsOverTls Enable DNS-over-TLS (DoT) on port 853.
 * @property daneRequireDnssec Require DNSSEC validation for DANE (always recommended).
 * @property noiseEnabled Whether Noise_NK bootstrap is enabled.
 * @property noiseServerAddr Noise bootstrap server address (e.g., "kms.example.com:8445").
 * @property noiseServerStaticKey Hex-encoded 32-byte Curve25519 server public key (64 hex chars).
 * @property spkiEnabled Whether SPKI-pinned TLS bootstrap is enabled.
 * @property spkiServerUrl Base URL for SPKI bootstrap (e.g., "https://kms.example.com:8443").
 * @property spkiPinSha256 Hex-encoded SHA-256 hash of server's SPKI (64 hex chars).
 * @property directEnabled Whether direct HTTPS bootstrap is enabled.
 * @property directServerUrl Base URL for direct HTTPS bootstrap.
 */
public data class BootstrapSettingsData(
    // Auto-bootstrap settings
    val autoBootstrapEnabled: Boolean = true,
    val methodOrder: List<BootstrapMethod> = BootstrapMethod.DEFAULT_ORDER,
    val perMethodTimeoutSeconds: Int = DEFAULT_PER_METHOD_TIMEOUT_SECONDS,

    // DANE settings
    val daneEnabled: Boolean = true,
    val daneServerUrl: String = "",
    val daneDnsServer: String = DEFAULT_DNS_SERVER,
    val daneDnsOverTls: Boolean = false,
    val daneRequireDnssec: Boolean = true,

    // Noise settings
    val noiseEnabled: Boolean = false,
    val noiseServerAddr: String = "",
    val noiseServerStaticKey: String = "",

    // SPKI settings
    val spkiEnabled: Boolean = false,
    val spkiServerUrl: String = "",
    val spkiPinSha256: String = "",

    // Direct HTTPS settings
    val directEnabled: Boolean = false,
    val directServerUrl: String = ""
) {
    /**
     * Check if a specific bootstrap method is enabled.
     *
     * @param method The bootstrap method to check.
     * @return True if the method is enabled, false otherwise.
     */
    public fun isMethodEnabled(method: BootstrapMethod): Boolean = when (method) {
        BootstrapMethod.DANE -> daneEnabled
        BootstrapMethod.NOISE -> noiseEnabled
        BootstrapMethod.SPKI -> spkiEnabled
        BootstrapMethod.DIRECT -> directEnabled
    }

    /**
     * Get the list of enabled methods in priority order.
     *
     * Returns methods from [methodOrder] that are currently enabled,
     * preserving the configured priority order.
     *
     * @return List of enabled methods in priority order.
     */
    public fun getEnabledMethods(): List<BootstrapMethod> =
        methodOrder.filter { isMethodEnabled(it) }

    /**
     * Check if any bootstrap method is properly configured.
     *
     * A method is considered configured if it is enabled and has the
     * required parameters set (e.g., server URL, keys, etc.).
     *
     * @return True if at least one method is ready for use.
     */
    public fun hasConfiguredMethod(): Boolean = getEnabledMethods().any { method ->
        when (method) {
            BootstrapMethod.DANE -> daneServerUrl.isNotBlank()
            BootstrapMethod.NOISE -> noiseServerAddr.isNotBlank() && noiseServerStaticKey.isNotBlank()
            BootstrapMethod.SPKI -> spkiServerUrl.isNotBlank() && spkiPinSha256.isNotBlank()
            BootstrapMethod.DIRECT -> directServerUrl.isNotBlank()
        }
    }

    /**
     * Check if the Noise server static key is valid.
     *
     * A valid key is exactly 64 hexadecimal characters (32 bytes).
     *
     * @return True if the key is valid or empty, false if malformed.
     */
    public fun isNoiseKeyValid(): Boolean {
        if (noiseServerStaticKey.isBlank()) return true
        return noiseServerStaticKey.length == HEX_KEY_LENGTH &&
            noiseServerStaticKey.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
    }

    /**
     * Check if the SPKI pin SHA-256 is valid.
     *
     * A valid pin is exactly 64 hexadecimal characters (32 bytes).
     *
     * @return True if the pin is valid or empty, false if malformed.
     */
    public fun isSpkiPinValid(): Boolean {
        if (spkiPinSha256.isBlank()) return true
        return spkiPinSha256.length == HEX_KEY_LENGTH &&
            spkiPinSha256.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
    }

    /**
     * Derive settings from a single server URL.
     *
     * Auto-populates the DANE, SPKI, and Direct server URLs from a single
     * base URL. Noise address is derived using the default Noise port.
     *
     * @param url The base server URL (e.g., "https://kms.example.com:8443").
     * @return A new [BootstrapSettingsData] with URLs populated.
     */
    public fun deriveFromUrl(url: String): BootstrapSettingsData {
        if (url.isBlank()) return this

        val parsed = try {
            URI.create(url)
        } catch (e: IllegalArgumentException) {
            return this
        }

        val host = parsed.host ?: return this
        val port = if (parsed.port > 0) parsed.port else DEFAULT_HTTPS_PORT
        val noisePort = if (port == DEFAULT_HTTPS_PORT) DEFAULT_NOISE_PORT else port + 2

        val httpsUrl = "https://$host:$port"
        val noiseAddr = "$host:$noisePort"

        return copy(
            daneServerUrl = httpsUrl,
            noiseServerAddr = noiseAddr,
            spkiServerUrl = httpsUrl,
            directServerUrl = httpsUrl
        )
    }

    /**
     * Get the [BootstrapTimeout] enum value matching [perMethodTimeoutSeconds].
     *
     * @return The matching [BootstrapTimeout], or null if the current value
     *         doesn't match any pre-defined timeout.
     */
    public fun getTimeoutEnum(): BootstrapTimeout? =
        BootstrapTimeout.fromSeconds(perMethodTimeoutSeconds)

    /**
     * Create a copy with a different timeout from the [BootstrapTimeout] enum.
     *
     * @param timeout The new timeout to use.
     * @return A new [BootstrapSettingsData] with the updated timeout.
     */
    public fun withTimeout(timeout: BootstrapTimeout): BootstrapSettingsData =
        copy(perMethodTimeoutSeconds = timeout.seconds)

    /**
     * Timeout in seconds for bootstrap operations.
     * Alias for [perMethodTimeoutSeconds] for compatibility with [BootstrapClient].
     */
    public val timeoutSeconds: Int
        get() = perMethodTimeoutSeconds


    /**
     * DANE configuration for [BootstrapClient].
     */
    public val daneConfig: DANEConfig
        get() = DANEConfig(
            serverUrl = daneServerUrl,
            dnsServer = daneDnsServer,
            dnsOverTls = daneDnsOverTls,
            requireDnssec = daneRequireDnssec
        )

    /**
     * Noise protocol configuration for [BootstrapClient].
     */
    public val noiseConfig: NoiseConfig
        get() = NoiseConfig(
            serverAddress = noiseServerAddr,
            serverStaticKey = noiseServerStaticKey
        )

    /**
     * SPKI pinning configuration for [BootstrapClient].
     */
    public val spkiConfig: SPKIConfig
        get() = SPKIConfig(
            serverUrl = spkiServerUrl,
            spkiPinSha256 = spkiPinSha256
        )

    /**
     * Direct HTTPS configuration for [BootstrapClient].
     */
    public val directConfig: DirectConfig
        get() = DirectConfig(serverUrl = directServerUrl)

    public companion object {
        /** Default per-method timeout in seconds (matches go-xkms). */
        public const val DEFAULT_PER_METHOD_TIMEOUT_SECONDS: Int = 15

        /** Default DNS server address (Google Public DNS). */
        public const val DEFAULT_DNS_SERVER: String = "8.8.8.8:53"

        /** Default HTTPS port. */
        public const val DEFAULT_HTTPS_PORT: Int = 443

        /** Default Noise bootstrap server port. */
        public const val DEFAULT_NOISE_PORT: Int = 8445

        /** Expected length of hex-encoded 32-byte keys/pins. */
        public const val HEX_KEY_LENGTH: Int = 64

        /**
         * Default settings with auto-bootstrap enabled and all methods available.
         */
        public val DEFAULT: BootstrapSettingsData = BootstrapSettingsData()

        /**
         * Settings for high-security environments requiring DANE or Noise.
         *
         * Direct HTTPS is disabled, forcing use of cryptographically
         * verified bootstrap methods.
         */
        public val HIGH_SECURITY: BootstrapSettingsData = BootstrapSettingsData(
            autoBootstrapEnabled = true,
            methodOrder = listOf(BootstrapMethod.DANE, BootstrapMethod.NOISE),
            daneEnabled = true,
            daneRequireDnssec = true,
            noiseEnabled = true,
            spkiEnabled = false,
            directEnabled = false
        )

        /**
         * Settings for development/testing with only direct HTTPS.
         *
         * All verification is disabled, using only the system trust store.
         * NOT recommended for production use.
         */
        public val DEVELOPMENT: BootstrapSettingsData = BootstrapSettingsData(
            autoBootstrapEnabled = true,
            methodOrder = listOf(BootstrapMethod.DIRECT),
            daneEnabled = false,
            noiseEnabled = false,
            spkiEnabled = false,
            directEnabled = true
        )
    }
}

/**
 * Extension property for the Bootstrap settings DataStore.
 */
private val Context.bootstrapSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "bootstrap_settings"
)

/**
 * Repository for persisting and retrieving bootstrap settings.
 *
 * Uses Jetpack DataStore for persistence, following the same pattern as
 * [TrustedComputingSettingsRepository] and [BiometricSettingsRepository].
 *
 * Usage:
 * ```kotlin
 * val repository = BootstrapSettingsRepository(context)
 *
 * // Observe settings changes
 * repository.settingsFlow.collect { settings ->
 *     if (settings.autoBootstrapEnabled) {
 *         configureBootstrapper(settings)
 *     }
 * }
 *
 * // Configure from a server URL
 * repository.deriveSettingsFromUrl("https://kms.example.com:8443")
 *
 * // Set Noise server key
 * repository.updateNoiseSettings(
 *     serverAddr = "kms.example.com:8445",
 *     serverStaticKey = "ab12cd34..." // 64 hex chars
 * )
 * ```
 *
 * @param context The Android context used to access DataStore.
 */
public class BootstrapSettingsRepository(
    private val context: Context
) {
    private val dataStore: DataStore<Preferences> = context.bootstrapSettingsDataStore

    /**
     * Flow of bootstrap settings that emits whenever settings change.
     *
     * Collectors will receive the current settings immediately upon subscription
     * and subsequent updates as they occur.
     */
    public val settingsFlow: Flow<BootstrapSettingsData> = dataStore.data.map { preferences ->
        mapPreferencesToSettings(preferences)
    }

    /**
     * Get the current bootstrap settings.
     *
     * @return The current [BootstrapSettingsData].
     */
    public suspend fun getSettings(): BootstrapSettingsData {
        return settingsFlow.first()
    }

    /**
     * Update all bootstrap settings at once.
     *
     * @param settings The new settings to persist.
     */
    public suspend fun updateSettings(settings: BootstrapSettingsData) {
        dataStore.edit { preferences ->
            // Auto-bootstrap
            preferences[KEY_AUTO_BOOTSTRAP_ENABLED] = settings.autoBootstrapEnabled
            preferences[KEY_METHOD_ORDER] = settings.methodOrder.joinToString(",") { it.name }
            preferences[KEY_PER_METHOD_TIMEOUT] = settings.perMethodTimeoutSeconds

            // DANE settings
            preferences[KEY_DANE_ENABLED] = settings.daneEnabled
            preferences[KEY_DANE_SERVER_URL] = settings.daneServerUrl
            preferences[KEY_DANE_DNS_SERVER] = settings.daneDnsServer
            preferences[KEY_DANE_DNS_OVER_TLS] = settings.daneDnsOverTls
            preferences[KEY_DANE_REQUIRE_DNSSEC] = settings.daneRequireDnssec

            // Noise settings
            preferences[KEY_NOISE_ENABLED] = settings.noiseEnabled
            preferences[KEY_NOISE_SERVER_ADDR] = settings.noiseServerAddr
            preferences[KEY_NOISE_SERVER_STATIC_KEY] = settings.noiseServerStaticKey

            // SPKI settings
            preferences[KEY_SPKI_ENABLED] = settings.spkiEnabled
            preferences[KEY_SPKI_SERVER_URL] = settings.spkiServerUrl
            preferences[KEY_SPKI_PIN_SHA256] = settings.spkiPinSha256

            // Direct HTTPS
            preferences[KEY_DIRECT_ENABLED] = settings.directEnabled
            preferences[KEY_DIRECT_SERVER_URL] = settings.directServerUrl
        }
    }

    /**
     * Enable or disable auto-bootstrap.
     *
     * @param enabled True to enable automatic bootstrap on connection.
     */
    public suspend fun updateAutoBootstrapEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_AUTO_BOOTSTRAP_ENABLED] = enabled
        }
    }

    /**
     * Update the bootstrap method priority order.
     *
     * @param methods The new method order, from highest to lowest priority.
     */
    public suspend fun updateMethodOrder(methods: List<BootstrapMethod>) {
        dataStore.edit { preferences ->
            preferences[KEY_METHOD_ORDER] = methods.joinToString(",") { it.name }
        }
    }

    /**
     * Update the per-method timeout.
     *
     * @param seconds Timeout in seconds for each bootstrap method attempt.
     */
    public suspend fun updatePerMethodTimeout(seconds: Int) {
        require(seconds > 0) { "Timeout must be positive" }
        dataStore.edit { preferences ->
            preferences[KEY_PER_METHOD_TIMEOUT] = seconds
        }
    }

    /**
     * Update the per-method timeout using a pre-defined [BootstrapTimeout].
     *
     * @param timeout The timeout enum value.
     */
    public suspend fun updatePerMethodTimeout(timeout: BootstrapTimeout) {
        updatePerMethodTimeout(timeout.seconds)
    }

    /**
     * Update DANE bootstrap settings.
     *
     * @param enabled Whether DANE bootstrap is enabled.
     * @param serverUrl Base URL for DANE bootstrap.
     * @param dnsServer DNS resolver address (e.g., "8.8.8.8:53").
     * @param dnsOverTls Enable DNS-over-TLS.
     * @param requireDnssec Require DNSSEC validation.
     */
    public suspend fun updateDaneSettings(
        enabled: Boolean? = null,
        serverUrl: String? = null,
        dnsServer: String? = null,
        dnsOverTls: Boolean? = null,
        requireDnssec: Boolean? = null
    ) {
        dataStore.edit { preferences ->
            enabled?.let { preferences[KEY_DANE_ENABLED] = it }
            serverUrl?.let { preferences[KEY_DANE_SERVER_URL] = it }
            dnsServer?.let { preferences[KEY_DANE_DNS_SERVER] = it }
            dnsOverTls?.let { preferences[KEY_DANE_DNS_OVER_TLS] = it }
            requireDnssec?.let { preferences[KEY_DANE_REQUIRE_DNSSEC] = it }
        }
    }

    /**
     * Update Noise bootstrap settings.
     *
     * @param enabled Whether Noise bootstrap is enabled.
     * @param serverAddr Noise server address (host:port).
     * @param serverStaticKey Hex-encoded 32-byte Curve25519 server public key.
     */
    public suspend fun updateNoiseSettings(
        enabled: Boolean? = null,
        serverAddr: String? = null,
        serverStaticKey: String? = null
    ) {
        dataStore.edit { preferences ->
            enabled?.let { preferences[KEY_NOISE_ENABLED] = it }
            serverAddr?.let { preferences[KEY_NOISE_SERVER_ADDR] = it }
            serverStaticKey?.let { preferences[KEY_NOISE_SERVER_STATIC_KEY] = it }
        }
    }

    /**
     * Update SPKI bootstrap settings.
     *
     * @param enabled Whether SPKI bootstrap is enabled.
     * @param serverUrl Base URL for SPKI bootstrap.
     * @param pinSha256 Hex-encoded SHA-256 hash of server's SPKI.
     */
    public suspend fun updateSpkiSettings(
        enabled: Boolean? = null,
        serverUrl: String? = null,
        pinSha256: String? = null
    ) {
        dataStore.edit { preferences ->
            enabled?.let { preferences[KEY_SPKI_ENABLED] = it }
            serverUrl?.let { preferences[KEY_SPKI_SERVER_URL] = it }
            pinSha256?.let { preferences[KEY_SPKI_PIN_SHA256] = it }
        }
    }

    /**
     * Update Direct HTTPS bootstrap settings.
     *
     * @param enabled Whether direct HTTPS bootstrap is enabled.
     * @param serverUrl Base URL for direct HTTPS bootstrap.
     */
    public suspend fun updateDirectSettings(
        enabled: Boolean? = null,
        serverUrl: String? = null
    ) {
        dataStore.edit { preferences ->
            enabled?.let { preferences[KEY_DIRECT_ENABLED] = it }
            serverUrl?.let { preferences[KEY_DIRECT_SERVER_URL] = it }
        }
    }

    /**
     * Derive and save settings from a single server URL.
     *
     * Auto-populates the DANE, SPKI, and Direct server URLs from the
     * provided base URL. Noise address is derived using the default port.
     *
     * @param url The base server URL (e.g., "https://kms.example.com:8443").
     */
    public suspend fun deriveSettingsFromUrl(url: String) {
        val current = getSettings()
        val derived = current.deriveFromUrl(url)
        updateSettings(derived)
    }

    /**
     * Check if a specific bootstrap method is enabled.
     *
     * @param method The bootstrap method to check.
     * @return True if the method is enabled.
     */
    public suspend fun isMethodEnabled(method: BootstrapMethod): Boolean {
        return getSettings().isMethodEnabled(method)
    }

    /**
     * Get the list of enabled methods in priority order.
     *
     * @return List of enabled methods in configured priority order.
     */
    public suspend fun getEnabledMethods(): List<BootstrapMethod> {
        return getSettings().getEnabledMethods()
    }

    /**
     * Reset all settings to their default values.
     */
    public suspend fun resetToDefaults() {
        updateSettings(BootstrapSettingsData.DEFAULT)
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
     * Map DataStore preferences to [BootstrapSettingsData].
     */
    private fun mapPreferencesToSettings(preferences: Preferences): BootstrapSettingsData {
        val methodOrderStr = preferences[KEY_METHOD_ORDER] ?: ""
        val methodOrder = BootstrapMethod.fromCommaSeparated(methodOrderStr)

        return BootstrapSettingsData(
            // Auto-bootstrap
            autoBootstrapEnabled = preferences[KEY_AUTO_BOOTSTRAP_ENABLED] ?: true,
            methodOrder = methodOrder,
            perMethodTimeoutSeconds = preferences[KEY_PER_METHOD_TIMEOUT]
                ?: BootstrapSettingsData.DEFAULT_PER_METHOD_TIMEOUT_SECONDS,

            // DANE settings
            daneEnabled = preferences[KEY_DANE_ENABLED] ?: true,
            daneServerUrl = preferences[KEY_DANE_SERVER_URL] ?: "",
            daneDnsServer = preferences[KEY_DANE_DNS_SERVER]
                ?: BootstrapSettingsData.DEFAULT_DNS_SERVER,
            daneDnsOverTls = preferences[KEY_DANE_DNS_OVER_TLS] ?: false,
            daneRequireDnssec = preferences[KEY_DANE_REQUIRE_DNSSEC] ?: true,

            // Noise settings
            noiseEnabled = preferences[KEY_NOISE_ENABLED] ?: false,
            noiseServerAddr = preferences[KEY_NOISE_SERVER_ADDR] ?: "",
            noiseServerStaticKey = preferences[KEY_NOISE_SERVER_STATIC_KEY] ?: "",

            // SPKI settings
            spkiEnabled = preferences[KEY_SPKI_ENABLED] ?: false,
            spkiServerUrl = preferences[KEY_SPKI_SERVER_URL] ?: "",
            spkiPinSha256 = preferences[KEY_SPKI_PIN_SHA256] ?: "",

            // Direct HTTPS
            directEnabled = preferences[KEY_DIRECT_ENABLED] ?: false,
            directServerUrl = preferences[KEY_DIRECT_SERVER_URL] ?: ""
        )
    }

    private companion object {
        // Auto-bootstrap keys
        val KEY_AUTO_BOOTSTRAP_ENABLED = booleanPreferencesKey("auto_bootstrap_enabled")
        val KEY_METHOD_ORDER = stringPreferencesKey("method_order")
        val KEY_PER_METHOD_TIMEOUT = intPreferencesKey("per_method_timeout_seconds")

        // DANE keys
        val KEY_DANE_ENABLED = booleanPreferencesKey("dane_enabled")
        val KEY_DANE_SERVER_URL = stringPreferencesKey("dane_server_url")
        val KEY_DANE_DNS_SERVER = stringPreferencesKey("dane_dns_server")
        val KEY_DANE_DNS_OVER_TLS = booleanPreferencesKey("dane_dns_over_tls")
        val KEY_DANE_REQUIRE_DNSSEC = booleanPreferencesKey("dane_require_dnssec")

        // Noise keys
        val KEY_NOISE_ENABLED = booleanPreferencesKey("noise_enabled")
        val KEY_NOISE_SERVER_ADDR = stringPreferencesKey("noise_server_addr")
        val KEY_NOISE_SERVER_STATIC_KEY = stringPreferencesKey("noise_server_static_key")

        // SPKI keys
        val KEY_SPKI_ENABLED = booleanPreferencesKey("spki_enabled")
        val KEY_SPKI_SERVER_URL = stringPreferencesKey("spki_server_url")
        val KEY_SPKI_PIN_SHA256 = stringPreferencesKey("spki_pin_sha256")

        // Direct HTTPS keys
        val KEY_DIRECT_ENABLED = booleanPreferencesKey("direct_enabled")
        val KEY_DIRECT_SERVER_URL = stringPreferencesKey("direct_server_url")
    }
}

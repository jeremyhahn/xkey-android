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
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Names the authority that signs device identity (IDevID) certificates.
 *
 * Device enrollment always needs an answer to "who signs?", and there are
 * exactly three: an xkms server, this phone, or nobody. The previous
 * `actAsCAServer` boolean could only express the last two.
 */
enum class CertificateAuthoritySource {
    /**
     * No certificate authority is configured, so enrollment cannot issue
     * anything. Pairing still works; it simply carries no device identity.
     */
    NONE,

    /**
     * This phone signs, using its own hardware-backed CA
     * ([com.automatethethings.xkey.ca.AndroidCA]).
     *
     * This is the standalone option, for a user with no key-management server.
     */
    THIS_DEVICE,

    /**
     * An xkms key-management server signs, reached at
     * [TrustedComputingSettingsData.xkmsEndpoint].
     *
     * Authoritative whenever it is configured: an enterprise deployment wants
     * one issuing CA, not one per phone.
     */
    XKMS
}

/**
 * Data class containing Trusted Computing settings.
 *
 * These settings control TPM-based device identity verification and
 * certificate authority integration for zero-trust device authentication.
 *
 * @property enabled Master switch for trusted computing features.
 * @property caSource Which authority signs device identity certificates.
 * @property xkmsEndpoint Base URL of the xkms server. Only meaningful when
 *                        [caSource] is [CertificateAuthoritySource.XKMS]; it is
 *                        also the URL the CA bundle is fetched from.
 * @property requireTrustedIDevID When true, reject connections from devices without
 *                                 a trusted Initial Device Identifier (IDevID) certificate.
 * @property requireFullAttestation When true, require TCG_CSR_IDEVID enrollment with
 *                                   Endorsement Key (EK) verification for device onboarding.
 * @property trustNewDevices When true, allow first-time pairing with devices that
 *                           have not been previously trusted. When false, devices must
 *                           be pre-provisioned in the trust store.
 * @property importToSystemStore When true, import CA certificates to the Android
 *                                system trust store for system-wide trust.
 */
data class TrustedComputingSettingsData(
    val enabled: Boolean = false,
    val caSource: CertificateAuthoritySource = CertificateAuthoritySource.NONE,
    val xkmsEndpoint: String? = null,
    val requireTrustedIDevID: Boolean = false,
    val requireFullAttestation: Boolean = false,
    val trustNewDevices: Boolean = true,
    val importToSystemStore: Boolean = false,
    val caSubjectOrganization: String = "",
    val caSubjectOU: String = "",
    val caSubjectLocality: String = "",
    val caSubjectProvince: String = "",
    val caSubjectCountry: String = "",
    val caSubjectCommonName: String = "",
    val platformCAAlias: String = "xkey_intermediate_ca"
) {
    /**
     * Indicates whether an xkms server should be asked to sign.
     *
     * Returns `true` if trusted computing is enabled, xkms is the selected
     * source, and an endpoint is configured. A selected-but-unconfigured xkms
     * source is not usable, which is why the endpoint is part of the test.
     */
    val useXkmsCA: Boolean
        get() = enabled &&
            caSource == CertificateAuthoritySource.XKMS &&
            !xkmsEndpoint.isNullOrBlank()

    /**
     * Indicates whether this phone's own CA should sign.
     */
    val useLocalCA: Boolean
        get() = enabled && caSource == CertificateAuthoritySource.THIS_DEVICE

    /**
     * Indicates whether device identity verification is active.
     *
     * Returns `true` if trusted computing is enabled and either trusted IDevID
     * or full attestation is required.
     */
    val isDeviceVerificationActive: Boolean
        get() = enabled && (requireTrustedIDevID || requireFullAttestation)

    companion object {
        /**
         * Default settings with trusted computing disabled.
         */
        val DEFAULT: TrustedComputingSettingsData = TrustedComputingSettingsData()

        /**
         * Permissive settings that trust new devices without verification.
         *
         * Suitable for initial setup and testing environments.
         */
        val PERMISSIVE: TrustedComputingSettingsData = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.THIS_DEVICE,
            trustNewDevices = true,
            requireTrustedIDevID = false,
            requireFullAttestation = false
        )

        /**
         * Strict settings requiring full device attestation.
         *
         * Suitable for high-security enterprise deployments where all
         * devices must be cryptographically verified before pairing. The xkms
         * endpoint is deliberately left unset: it is site-specific, and
         * [useXkmsCA] stays false until an operator supplies it.
         */
        val STRICT: TrustedComputingSettingsData = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.XKMS,
            requireTrustedIDevID = true,
            requireFullAttestation = true,
            trustNewDevices = false
        )
    }
}

/**
 * Extension property for the Trusted Computing settings DataStore.
 */
private val Context.trustedComputingDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "trusted_computing_settings"
)

/**
 * Repository for persisting and retrieving Trusted Computing settings.
 *
 * Uses Jetpack DataStore for persistence, following the same pattern as
 * [BiometricSettingsRepository].
 *
 * Usage:
 * ```kotlin
 * val repository = TrustedComputingSettingsRepository(context)
 *
 * // Observe settings changes
 * repository.settingsFlow.collect { settings ->
 *     if (settings.enabled) {
 *         configureTPMVerification(settings)
 *     }
 * }
 *
 * // Enable trusted computing with full attestation
 * repository.updateSettings(
 *     TrustedComputingSettingsData(
 *         enabled = true,
 *         requireFullAttestation = true,
 *         caSource = CertificateAuthoritySource.XKMS,
 *         xkmsEndpoint = "https://xkms.example.com"
 *     )
 * )
 * ```
 *
 * @param context The Android context used to access DataStore.
 */
class TrustedComputingSettingsRepository(
    private val context: Context
) {
    private val dataStore: DataStore<Preferences> = context.trustedComputingDataStore

    /**
     * Flow of Trusted Computing settings that emits whenever settings change.
     *
     * Collectors will receive the current settings immediately upon subscription
     * and subsequent updates as they occur.
     */
    val settingsFlow: Flow<TrustedComputingSettingsData> = dataStore.data.map { preferences ->
        mapPreferencesToSettings(preferences)
    }

    /**
     * Get the current Trusted Computing settings.
     *
     * @return The current [TrustedComputingSettingsData].
     */
    suspend fun getSettings(): TrustedComputingSettingsData {
        return settingsFlow.first()
    }

    /**
     * Update all Trusted Computing settings at once.
     *
     * @param settings The new settings to persist.
     */
    suspend fun updateSettings(settings: TrustedComputingSettingsData) {
        dataStore.edit { preferences ->
            preferences[KEY_ENABLED] = settings.enabled
            preferences[KEY_CA_SOURCE] = settings.caSource.name
            if (settings.xkmsEndpoint != null) {
                preferences[KEY_XKMS_ENDPOINT] = settings.xkmsEndpoint
            } else {
                preferences.remove(KEY_XKMS_ENDPOINT)
            }
            preferences[KEY_REQUIRE_TRUSTED_IDEVID] = settings.requireTrustedIDevID
            preferences[KEY_REQUIRE_FULL_ATTESTATION] = settings.requireFullAttestation
            preferences[KEY_TRUST_NEW_DEVICES] = settings.trustNewDevices
            preferences[KEY_IMPORT_TO_SYSTEM_STORE] = settings.importToSystemStore
            preferences[KEY_CA_SUBJECT_ORG] = settings.caSubjectOrganization
            preferences[KEY_CA_SUBJECT_OU] = settings.caSubjectOU
            preferences[KEY_CA_SUBJECT_LOCALITY] = settings.caSubjectLocality
            preferences[KEY_CA_SUBJECT_PROVINCE] = settings.caSubjectProvince
            preferences[KEY_CA_SUBJECT_COUNTRY] = settings.caSubjectCountry
            preferences[KEY_CA_SUBJECT_CN] = settings.caSubjectCommonName
            preferences[KEY_PLATFORM_CA_ALIAS] = settings.platformCAAlias
        }
    }

    /**
     * Enable or disable trusted computing features.
     *
     * @param enabled True to enable, false to disable.
     */
    suspend fun updateEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_ENABLED] = enabled
        }
    }

    /**
     * Select the authority that signs device identity certificates.
     *
     * @param source The certificate authority to use.
     */
    suspend fun updateCASource(source: CertificateAuthoritySource) {
        dataStore.edit { preferences ->
            preferences[KEY_CA_SOURCE] = source.name
        }
    }

    /**
     * Update the xkms server endpoint.
     *
     * Only consulted when [CertificateAuthoritySource.XKMS] is selected; a
     * selected-but-unconfigured xkms source is not usable.
     *
     * @param url The xkms endpoint, or null to clear.
     */
    suspend fun updateXkmsEndpoint(url: String?) {
        dataStore.edit { preferences ->
            if (url != null) {
                preferences[KEY_XKMS_ENDPOINT] = url
            } else {
                preferences.remove(KEY_XKMS_ENDPOINT)
            }
        }
    }

    /**
     * Set whether trusted IDevID is required for connections.
     *
     * @param required True to require trusted IDevID, false otherwise.
     */
    suspend fun updateRequireTrustedIDevID(required: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_REQUIRE_TRUSTED_IDEVID] = required
        }
    }

    /**
     * Set whether full TCG_CSR_IDEVID attestation is required.
     *
     * @param required True to require full attestation, false otherwise.
     */
    suspend fun updateRequireFullAttestation(required: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_REQUIRE_FULL_ATTESTATION] = required
        }
    }

    /**
     * Set whether new devices should be automatically trusted on first pairing.
     *
     * @param trust True to trust new devices, false to require pre-provisioning.
     */
    suspend fun updateTrustNewDevices(trust: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_TRUST_NEW_DEVICES] = trust
        }
    }

    /**
     * Set whether CA certificates should be imported to the Android system store.
     *
     * @param importToStore True to import to system store, false otherwise.
     */
    suspend fun updateImportToSystemStore(importToStore: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_IMPORT_TO_SYSTEM_STORE] = importToStore
        }
    }

    /**
     * Update the CA subject configuration fields.
     */
    suspend fun updateCASubject(
        org: String,
        ou: String,
        locality: String,
        province: String,
        country: String,
        cn: String
    ) {
        dataStore.edit { preferences ->
            preferences[KEY_CA_SUBJECT_ORG] = org
            preferences[KEY_CA_SUBJECT_OU] = ou
            preferences[KEY_CA_SUBJECT_LOCALITY] = locality
            preferences[KEY_CA_SUBJECT_PROVINCE] = province
            preferences[KEY_CA_SUBJECT_COUNTRY] = country
            preferences[KEY_CA_SUBJECT_CN] = cn
        }
    }

    /**
     * Update the platform CA alias (which CA signs device certificates).
     *
     * @param alias Either "xkey_root_ca" or "xkey_intermediate_ca"
     */
    suspend fun updatePlatformCAAlias(alias: String) {
        dataStore.edit { preferences ->
            preferences[KEY_PLATFORM_CA_ALIAS] = alias
        }
    }

    /**
     * Reset all settings to their default values.
     */
    suspend fun resetToDefaults() {
        updateSettings(TrustedComputingSettingsData.DEFAULT)
    }

    /**
     * Clear all stored settings.
     *
     * After calling this method, [settingsFlow] will emit default values
     * until new settings are saved.
     */
    suspend fun clearSettings() {
        dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    /**
     * Reads the selected CA, migrating installs written before the choice
     * existed.
     *
     * The old model was a single `act_as_ca_server` boolean, which could not
     * say "xkms signs". A stored `true` meant this phone signs; a stored
     * `false` meant an external CA whose only expressible form was a URL, so a
     * URL present without a source is read as xkms. The legacy keys are left in
     * place rather than deleted, so a downgrade still finds what it wrote.
     */
    private fun readCASource(preferences: Preferences): CertificateAuthoritySource {
        preferences[KEY_CA_SOURCE]?.let { stored ->
            return runCatching { CertificateAuthoritySource.valueOf(stored) }
                .getOrDefault(CertificateAuthoritySource.NONE)
        }
        if (preferences[KEY_ACT_AS_CA_SERVER] == true) {
            return CertificateAuthoritySource.THIS_DEVICE
        }
        if (!preferences[KEY_CA_SERVER_URL].isNullOrBlank()) {
            return CertificateAuthoritySource.XKMS
        }
        return CertificateAuthoritySource.NONE
    }

    /**
     * Map DataStore preferences to [TrustedComputingSettingsData].
     */
    private fun mapPreferencesToSettings(preferences: Preferences): TrustedComputingSettingsData {
        return TrustedComputingSettingsData(
            enabled = preferences[KEY_ENABLED] ?: false,
            caSource = readCASource(preferences),
            xkmsEndpoint = preferences[KEY_XKMS_ENDPOINT] ?: preferences[KEY_CA_SERVER_URL],
            requireTrustedIDevID = preferences[KEY_REQUIRE_TRUSTED_IDEVID] ?: false,
            requireFullAttestation = preferences[KEY_REQUIRE_FULL_ATTESTATION] ?: false,
            trustNewDevices = preferences[KEY_TRUST_NEW_DEVICES] ?: true,
            importToSystemStore = preferences[KEY_IMPORT_TO_SYSTEM_STORE] ?: false,
            caSubjectOrganization = preferences[KEY_CA_SUBJECT_ORG] ?: "",
            caSubjectOU = preferences[KEY_CA_SUBJECT_OU] ?: "",
            caSubjectLocality = preferences[KEY_CA_SUBJECT_LOCALITY] ?: "",
            caSubjectProvince = preferences[KEY_CA_SUBJECT_PROVINCE] ?: "",
            caSubjectCountry = preferences[KEY_CA_SUBJECT_COUNTRY] ?: "",
            caSubjectCommonName = preferences[KEY_CA_SUBJECT_CN] ?: "",
            platformCAAlias = preferences[KEY_PLATFORM_CA_ALIAS] ?: "xkey_intermediate_ca"
        )
    }

    private companion object {
        val KEY_ENABLED = booleanPreferencesKey("enabled")
        val KEY_CA_SOURCE = stringPreferencesKey("ca_source")
        val KEY_XKMS_ENDPOINT = stringPreferencesKey("xkms_endpoint")

        /** Superseded by [KEY_CA_SOURCE]; read only, for migration. */
        val KEY_ACT_AS_CA_SERVER = booleanPreferencesKey("act_as_ca_server")

        /** Superseded by [KEY_XKMS_ENDPOINT]; read only, for migration. */
        val KEY_CA_SERVER_URL = stringPreferencesKey("ca_server_url")
        val KEY_REQUIRE_TRUSTED_IDEVID = booleanPreferencesKey("require_trusted_idevid")
        val KEY_REQUIRE_FULL_ATTESTATION = booleanPreferencesKey("require_full_attestation")
        val KEY_TRUST_NEW_DEVICES = booleanPreferencesKey("trust_new_devices")
        val KEY_IMPORT_TO_SYSTEM_STORE = booleanPreferencesKey("import_to_system_store")
        val KEY_CA_SUBJECT_ORG = stringPreferencesKey("ca_subject_org")
        val KEY_CA_SUBJECT_OU = stringPreferencesKey("ca_subject_ou")
        val KEY_CA_SUBJECT_LOCALITY = stringPreferencesKey("ca_subject_locality")
        val KEY_CA_SUBJECT_PROVINCE = stringPreferencesKey("ca_subject_province")
        val KEY_CA_SUBJECT_COUNTRY = stringPreferencesKey("ca_subject_country")
        val KEY_CA_SUBJECT_CN = stringPreferencesKey("ca_subject_cn")
        val KEY_PLATFORM_CA_ALIAS = stringPreferencesKey("platform_ca_alias")
    }
}

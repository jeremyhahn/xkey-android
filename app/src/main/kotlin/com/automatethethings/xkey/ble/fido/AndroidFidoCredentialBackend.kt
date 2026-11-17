/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ble.fido

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Raises the phone's user verification prompt for a BLE ceremony. */
interface FidoUserPrompt {
    /** Whether a biometric or device credential is enrolled and a prompt can be shown. */
    val available: Boolean

    suspend fun verify(rpId: String, registering: Boolean): UserCheck
}

/**
 * The phone's passkeys for the FIDO BLE authenticator.
 *
 * A BLE client is not a paired xkey desktop: it has no Noise static key, so
 * [SharePermission] sees no peer. Only passkeys shared with all peers are
 * offered; private passkeys and passkeys shared with selected peers are never
 * listed or signed with. The policy is read again under the signing path, so a
 * passkey made private while its prompt was open is refused.
 *
 * The counter comes from the one [PasskeySignCounter] the credential provider
 * and the JSON-RPC phone backend share, and the key signs inside Keystore.
 */
class AndroidFidoCredentialBackend(
    private val keyDao: KeyDao,
    private val credentialDao: CredentialMetadataDao,
    private val sharePermission: SharePermission,
    private val signCounter: PasskeySignCounter,
    private val keystoreManager: KeystoreManager,
    private val userPrompt: FidoUserPrompt?,
    private val settings: () -> BiometricSettingsData
) : FidoCredentialBackend {

    override val userVerificationAvailable: Boolean
        get() = userPrompt?.available == true

    override val strictUserVerification: Boolean
        get() = settings().strictUserVerification

    override suspend fun credentials(rpId: String): List<FidoCredential> =
        keyDao.getFido2ByRpId(rpId)
            .filter { it.keyType == KeyTypeFido2 && it.rpId == rpId && shared(it) }
            .mapNotNull { entity ->
                val id = decodeId(entity.keyId) ?: return@mapNotNull null
                FidoCredential(
                    id = id,
                    rpId = rpId,
                    userHandle = entity.userId?.let { decodeId(it) },
                    userName = entity.userName,
                    userDisplayName = entity.userDisplayName,
                    discoverable = entity.isDiscoverable
                )
            }

    override suspend fun checkUser(rpId: String, registering: Boolean): UserCheck {
        val prompt = userPrompt ?: return UserCheck.UNAVAILABLE
        if (!prompt.available) return UserCheck.UNAVAILABLE
        return prompt.verify(rpId, registering)
    }

    override suspend fun sign(
        credential: FidoCredential,
        authenticatorData: (signCount: Long) -> ByteArray,
        clientDataHash: ByteArray
    ): SignedAssertion {
        val keyId = encodeId(credential.id)
        val entity = keyDao.getByKeyId(keyId)
        if (entity == null || entity.keyType != KeyTypeFido2 || entity.rpId != credential.rpId || !shared(entity)) {
            throw FidoRefusedException(Ctap2.ERR_NO_CREDENTIALS, "Passkey is gone or no longer shared")
        }
        val count = signCounter.next(keyId)
        val authData = authenticatorData(count)
        val dataHash = MessageDigest.getInstance("SHA-256").digest(authData + clientDataHash)
        val signature = keystoreManager.signWithoutBiometric(credentialId = keyId, dataHash = dataHash)
        Log.i(TAG, "Signed a CTAP2 assertion over BLE, rpId=${credential.rpId}, signCount=$count")
        runCatching {
            AuditLogger.logFido2Authentication(
                keyId = keyId,
                keyLabel = entity.rpName ?: entity.label,
                rpId = credential.rpId
            )
        }
        return SignedAssertion(authData, signature)
    }

    override suspend fun create(request: CredentialRequest): NewCredential {
        val rawId = ByteArray(CREDENTIAL_ID_BYTES).also { SecureRandom().nextBytes(it) }
        val keyId = encodeId(rawId)
        // Not auth-bound: the phone's prompt gates every use, as on the
        // JSON-RPC path, and an auth-bound key could not sign after it.
        val cose = keystoreManager.generateKeyWithAuthDuration(
            credentialId = keyId,
            authDurationSeconds = -1,
            requireStrongBox = false
        )
        val userId = encodeId(request.userHandle)
        val rpName = request.rpName ?: request.rpId
        try {
            credentialDao.insert(
                CredentialMetadataEntity(
                    credentialId = keyId,
                    rpId = request.rpId,
                    rpName = rpName,
                    userId = userId,
                    userName = request.userName ?: "",
                    userDisplayName = request.userDisplayName ?: request.userName ?: "",
                    publicKeyCose = cose,
                    signCount = 0,
                    isDiscoverable = request.discoverable
                )
            )
            keyDao.insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = KeyTypeFido2,
                    algorithm = "ES256",
                    label = rpName,
                    publicKeyCose = cose,
                    keySizeBits = 256,
                    biometricRequired = false,
                    authDurationSeconds = -1,
                    exportable = false,
                    shareable = false,
                    source = "local",
                    createdAt = System.currentTimeMillis(),
                    rpId = request.rpId,
                    rpName = rpName,
                    userId = userId,
                    userName = request.userName,
                    userDisplayName = request.userDisplayName,
                    isDiscoverable = request.discoverable,
                    signCount = 0,
                    // Made by a BLE client, which has no paired identity: shared
                    // with all peers so that client can use it again.
                    sharingPolicy = SharingPolicyType.ALL_PEERS
                )
            )
        } catch (e: Exception) {
            keystoreManager.deleteKey(keyId)
            throw e
        }
        Log.i(TAG, "Created a passkey over BLE, rpId=${request.rpId}")
        runCatching {
            AuditLogger.logFido2Registration(
                keyId = keyId,
                keyLabel = rpName,
                rpId = request.rpId,
                userName = request.userName ?: ""
            )
        }
        return NewCredential(rawId, cose)
    }

    private suspend fun shared(entity: KeyEntity): Boolean = sharePermission.canShare(entity, null)

    private companion object {
        const val TAG = "FidoBleBackend"
        const val KeyTypeFido2 = "fido2"
        const val CREDENTIAL_ID_BYTES = 32

        fun encodeId(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)

        /** Passkey ids and user handles are stored base64url; anything else is skipped. */
        fun decodeId(text: String): ByteArray? = try {
            Base64.getUrlDecoder().decode(text.trimEnd('='))
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}

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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborEncoder
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.protocol.KeyTypes
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.atomic.AtomicInteger

/**
 * MakeCredential then GetAssertion through [Ctap2Authenticator] and
 * [AndroidFidoCredentialBackend] on the app's real database and the real
 * AndroidKeyStore, with a prompt fake that approves. The assertion is
 * verified with the COSE key MakeCredential returned, as a relying party
 * verifies it. The passkey, its metadata and its Keystore key are removed
 * in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class Ctap2KeystoreRoundTripTest {

    private lateinit var context: Context
    private lateinit var db: XKeyDatabase
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var authenticator: Ctap2Authenticator

    private val runId = System.currentTimeMillis().toString(36)
    private val rpId = "ctap2-keystore-$runId.example"
    private val verifications = AtomicInteger()

    /** Approves every ceremony; a passkey made over BLE never needs a key-bound prompt. */
    private val prompt = object : FidoUserPrompt {
        override val available = true

        override suspend fun verify(rpId: String, registering: Boolean): UserCheck {
            verifications.incrementAndGet()
            return UserCheck.VERIFIED
        }

        override suspend fun chooseAccount(rpId: String, accounts: List<String>): Int = 0

        override suspend fun signWithKey(
            keyId: String,
            keyAlias: String,
            rpId: String,
            signedData: suspend () -> ByteArray
        ): ByteArray = throw AssertionError("a BLE passkey's key is not auth-bound and signs without a key-bound prompt")
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        db = XKeyDatabase.getInstance(context)
        keystoreManager = KeystoreManager(context)
        val pending = java.io.File(context.cacheDir, "ctap2-keystore-pending-$runId")
        authenticator = Ctap2Authenticator(
            AndroidFidoCredentialBackend(
                keyDao = db.keyDao(),
                credentialDao = db.credentialMetadataDao(),
                sharePermission = SharePermission(
                    db.keySharingPolicyDao(),
                    PairedDeviceRepository(context),
                    KeyPolicyStore.of(db, keystoreManager)
                ),
                signCounter = PasskeySignCounter(db.credentialMetadataDao(), db.keyDao()),
                keystoreManager = keystoreManager,
                userPrompt = prompt,
                settings = { BiometricSettingsData() },
                pendingKeyDeletions = FilePendingKeyDeletions(pending)
            )
        )
    }

    @After
    fun tearDown() = runBlocking {
        for (row in db.keyDao().getFido2ByRpId(rpId)) {
            runCatching { keystoreManager.deleteKey(row.keyId, UserKeyKind.CREDENTIAL) }
            runCatching { db.keySharingPolicyDao().clearPoliciesForKey(row.keyId) }
            runCatching { db.keyDao().deleteByKeyId(row.keyId) }
        }
        runCatching { db.credentialMetadataDao().deleteByRpId(rpId) }
        java.io.File(context.cacheDir, "ctap2-keystore-pending-$runId").delete()
        Unit
    }

    @Test
    fun makeCredentialThenGetAssertionSignsWithTheKeystoreKey() = runBlocking {
        val made = ok(
            byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte()) + CborEncoder.encode(
                mapOf(
                    1 to sha256("make-credential".toByteArray()),
                    2 to mapOf("id" to rpId, "name" to "Keystore Round Trip"),
                    3 to mapOf("id" to USER_HANDLE, "name" to "alice", "displayName" to "Alice"),
                    4 to listOf(mapOf("alg" to -7, "type" to "public-key")),
                    7 to mapOf("rk" to true, "up" to true)
                )
            )
        )
        assertEquals("none", made[1L])
        val authData = made[2L] as ByteArray
        assertArrayEquals(sha256(rpId.toByteArray()), authData.copyOfRange(0, 32))
        assertEquals(FLAG_UP or FLAG_UV or FLAG_AT, authData[32].toInt() and 0xFF)
        val idLength = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val credentialId = authData.copyOfRange(55, 55 + idLength)
        val cose = CborDecoder.decode(authData.copyOfRange(55 + idLength, authData.size)) as Map<*, *>
        assertEquals(2L, cose[1L])
        assertEquals(-7L, cose[3L])
        assertEquals(1L, cose[-1L])
        val publicKey = p256(cose[-2L] as ByteArray, cose[-3L] as ByteArray)

        // The stored passkey's Keystore key is the one the COSE key names.
        val row = db.keyDao().getFido2ByRpId(rpId).single()
        assertNotNull(db.credentialMetadataDao().getByCredentialId(row.keyId))
        val alias = keystoreManager.keyRowAlias(row.keyId, KeyTypes.FIDO2, row.publicKeyDer)
        assertArrayEquals(publicKey.encoded, keystoreManager.publicKeyDERAt(alias))

        for (expected in 1L..2L) {
            val clientDataHash = sha256("get-assertion-$expected".toByteArray())
            val params = mutableMapOf<Any, Any?>(1 to rpId, 2 to clientDataHash, 5 to mapOf("up" to true))
            // The first names the passkey in allowList, the second discovers it.
            if (expected == 1L) params[3] = listOf(mapOf("id" to credentialId, "type" to "public-key"))
            val assertion = ok(byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte()) + CborEncoder.encode(params))

            assertArrayEquals(credentialId, (assertion[1L] as Map<*, *>)["id"] as ByteArray)
            val signedAuthData = assertion[2L] as ByteArray
            assertArrayEquals(sha256(rpId.toByteArray()), signedAuthData.copyOfRange(0, 32))
            assertEquals(FLAG_UP or FLAG_UV, signedAuthData[32].toInt() and 0xFF)
            assertEquals(expected, BigInteger(1, signedAuthData.copyOfRange(33, 37)).toLong())
            val verifier = Signature.getInstance("SHA256withECDSA").apply {
                initVerify(publicKey)
                update(signedAuthData + clientDataHash)
            }
            assertTrue("the Keystore signature verifies with the COSE key", verifier.verify(assertion[3L] as ByteArray))
        }
        assertEquals(2L, db.keyDao().getByKeyId(row.keyId)!!.signCount)
        assertEquals(3, verifications.get())
    }

    private suspend fun ok(request: ByteArray): Map<*, *> {
        val response = authenticator.handle(request) {}
        assertEquals("CTAP2 status", Ctap2.OK, response[0].toInt() and 0xFF)
        return CborDecoder.decode(response.copyOfRange(1, response.size)) as Map<*, *>
    }

    private companion object {
        val USER_HANDLE = byteArrayOf(5, 6, 7, 8)
        const val FLAG_UP = 0x01
        const val FLAG_UV = 0x04
        const val FLAG_AT = 0x40

        fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

        fun p256(x: ByteArray, y: ByteArray): PublicKey {
            val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
            return KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), params))
        }
    }
}

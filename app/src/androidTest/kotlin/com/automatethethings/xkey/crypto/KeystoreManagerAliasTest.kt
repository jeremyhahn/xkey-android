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
package com.automatethethings.xkey.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyGenerator

/**
 * Instrumented tests for [KeystoreManager]'s alias resolution and public-key
 * exports.
 *
 * xKey keeps keys in two alias namespaces -- `xkey_credential_<id>` for FIDO2
 * credentials and `xkey_key_<id>` for everything the pairing protocol creates --
 * and `resolveKeystoreAlias` is what lets one identifier reach either. Two
 * shipped defects came from paths that skipped it and built the FIDO2 alias
 * directly (the COSE export and `signWithoutBiometric`), so both are pinned
 * here, as is the one accessor that still has not been converted.
 *
 * Every alias created here is removed in `tearDown`, along with the audit rows
 * `KeystoreManager` writes, because other suites assert on live key counts.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreManagerAliasTest {

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var keyStore: KeyStore

    private val credentialIds = mutableListOf<String>()
    private val generalKeyIds = mutableListOf<String>()
    private val rawAliases = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
        keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    }

    @After
    fun tearDown() {
        val dao = XKeyDatabase.getInstance(context).auditLogDao()
        (credentialIds + generalKeyIds).forEach { keyId ->
            runCatching { keystoreManager.deleteKey(keyId) }
            runCatching { keystoreManager.deleteGeneralKey(keyId) }
            runCatching { runBlocking { dao.deleteByKeyId(keyId) } }
        }
        rawAliases.forEach { alias -> runCatching { keyStore.deleteEntry(alias) } }
        // Ed25519 private keys are held in EncryptedSharedPreferences, not the
        // Keystore, so deleting the alias above would not remove them.
        runCatching {
            val prefs = EncryptedSharedPreferences.create(
                context,
                "xkey_ed25519_keys",
                MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            val editor = prefs.edit()
            generalKeyIds.forEach { editor.remove("xkey_key_$it") }
            editor.apply()
        }
        // Attestation uses a throwaway alias; make sure none outlives the suite.
        runCatching {
            keyStore.aliases().toList()
                .filter { it.startsWith("xkey_attest_") }
                .forEach { keyStore.deleteEntry(it) }
        }
        credentialIds.clear()
        generalKeyIds.clear()
        rawAliases.clear()
    }

    private fun newCredentialId(label: String): String =
        "cred-$label-${System.nanoTime()}".also { credentialIds.add(it) }

    private fun newGeneralKeyId(label: String): String =
        "key-$label-${System.nanoTime()}".also { generalKeyIds.add(it) }

    private fun generalKey(algorithm: String, label: String): Pair<String, ByteArray> {
        val keyId = newGeneralKeyId(label)
        val der = runBlocking {
            keystoreManager.generateKeyForAlgorithm(keyId, algorithm, -1, false)
        }
        return keyId to der
    }

    private fun credentialKey(label: String): String {
        val credentialId = newCredentialId(label)
        runBlocking { keystoreManager.generateKey(credentialId, requireBiometric = false) }
        return credentialId
    }

    /** An AES key under a bare alias, i.e. one xKey did not namespace. */
    private fun rawKeystoreAlias(label: String): String {
        val alias = "foreign-$label-${System.nanoTime()}"
        rawAliases.add(alias)
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER).apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
        return alias
    }

    // ------------------------------------------------------ alias resolution

    @Test
    fun resolvesACredentialKeyInTheFido2Namespace() {
        val credentialId = credentialKey("resolve")

        assertEquals("xkey_credential_$credentialId", keystoreManager.resolveKeystoreAlias(credentialId))
    }

    @Test
    fun resolvesAGeneralKeyInTheProtocolNamespace() {
        val (keyId, _) = generalKey("ES256", "resolve")

        assertEquals("xkey_key_$keyId", keystoreManager.resolveKeystoreAlias(keyId))
    }

    @Test
    fun resolvesAnAliasThatXkeyDidNotNamespace() {
        val alias = rawKeystoreAlias("resolve")

        assertEquals(alias, keystoreManager.resolveKeystoreAlias(alias))
    }

    @Test
    fun resolvesNothingForAnIdentifierWithNoKey() {
        assertNull(keystoreManager.resolveKeystoreAlias("missing-${System.nanoTime()}"))
    }

    @Test
    fun theCredentialNamespaceIsTriedBeforeTheGeneralOne() {
        val sharedId = "shared-${System.nanoTime()}"
        credentialIds.add(sharedId)
        generalKeyIds.add(sharedId)
        runBlocking {
            keystoreManager.generateKeyForAlgorithm(sharedId, "ES256", -1, false)
            keystoreManager.generateKey(sharedId, requireBiometric = false)
        }

        assertEquals("xkey_credential_$sharedId", keystoreManager.resolveKeystoreAlias(sharedId))
    }

    // -------------------------------------------- exports across both spaces

    @Test
    fun exportsAGeneralKeyAsCoseEvenThoughItIsNotAFido2Credential() {
        // Regression: getCOSEPublicKey used to build the FIDO2 alias directly,
        // so local.getPublicKey with format=cose failed for every protocol key.
        val (keyId, _) = generalKey("ES256", "cose")

        val cose = keystoreManager.getCOSEPublicKey(keyId)

        assertNotNull(cose)
        assertTrue(cose!!.isNotEmpty())
    }

    @Test
    fun exportsAFido2CredentialAsCose() {
        val credentialId = credentialKey("cose")

        assertNotNull(keystoreManager.getCOSEPublicKey(credentialId))
    }

    @Test
    fun returnsNoCoseKeyForAnUnknownIdentifier() {
        assertNull(keystoreManager.getCOSEPublicKey("missing-${System.nanoTime()}"))
    }

    @Test
    fun signsAGeneralKeyWithoutABiometricPrompt() {
        // Regression: signWithoutBiometric used to build the FIDO2 alias, so a
        // passkey created through the general key path could never be signed.
        val (keyId, der) = generalKey("ES256", "sign")
        val payload = "protocol-signed payload".toByteArray()

        val signature = runBlocking { keystoreManager.signWithoutBiometric(keyId, payload) }

        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)))
            update(payload)
        }
        assertTrue(verifier.verify(signature))
    }

    @Test
    fun signingWithoutABiometricRejectsAnUnknownIdentifier() {
        assertThrows(KeyNotFoundException::class.java) {
            runBlocking {
                keystoreManager.signWithoutBiometric("missing-${System.nanoTime()}", ByteArray(32))
            }
        }
    }

    /**
     * Every accessor resolves both alias namespaces. `getPublicKey` used to
     * build the FIDO2-only alias, so a key created through
     * `generateKeyForAlgorithm` was invisible to it while every other export
     * found it — the same defect that broke COSE export and prompt-backed
     * signing for desktop-created passkeys.
     */
    @Test
    fun getPublicKeyResolvesBothNamespaces() {
        val (keyId, der) = generalKey("ES256", "public-key-namespace")

        assertNotNull("the DER export resolves both namespaces", keystoreManager.getPublicKeyDER(keyId))
        val publicKey = keystoreManager.getPublicKey(keyId)
        assertNotNull("getPublicKey must resolve them too", publicKey)
        assertArrayEquals(der, publicKey!!.encoded)
    }

    // ---------------------------------------------------------- key material

    @Test
    fun exportsThePublicKeyAsDer() {
        val (keyId, der) = generalKey("ES256", "der")

        assertArrayEquals(der, keystoreManager.getPublicKeyDER(keyId))
        assertNull(keystoreManager.getPublicKeyDER("missing-${System.nanoTime()}"))
    }

    @Test
    fun exportsThePublicKeyAsPem() {
        val (keyId, der) = generalKey("ES256", "pem")

        val pem = keystoreManager.getPublicKeyPEM(keyId)!!
        val lines = pem.lines()

        assertEquals("-----BEGIN PUBLIC KEY-----", lines.first())
        assertEquals("-----END PUBLIC KEY-----", lines.last())
        val body = lines.subList(1, lines.size - 1)
        assertTrue("PEM body must wrap at 64 characters", body.all { it.length <= 64 })
        assertArrayEquals(der, Base64.getDecoder().decode(body.joinToString("")))
    }

    @Test
    fun returnsNoPemForAnUnknownIdentifier() {
        assertNull(keystoreManager.getPublicKeyPEM("missing-${System.nanoTime()}"))
    }

    @Test
    fun exportsEveryEcCurveInOpensshWireFormat() {
        mapOf("ES256" to "nistp256", "ES384" to "nistp384", "ES512" to "nistp521")
            .forEach { (algorithm, curve) ->
                val (keyId, _) = generalKey(algorithm, "ssh-$curve")

                val authorizedKey = keystoreManager.getPublicKeySSH(keyId)!!
                val (keyType, encoded) = authorizedKey.split(" ", limit = 2)
                val blob = readSshBlob(Base64.getDecoder().decode(encoded))

                assertEquals("ecdsa-sha2-$curve", keyType)
                assertEquals(keyType, String(blob[0], Charsets.UTF_8))
                assertEquals(curve, String(blob[1], Charsets.UTF_8))
                assertEquals("uncompressed point", 0x04.toByte(), blob[2][0])
                assertEquals("x and y are equal length", 1, blob[2].size % 2)
            }
    }

    @Test
    fun exportsAnRsaKeyInOpensshWireFormat() {
        val (keyId, _) = generalKey("RS256", "ssh-rsa")

        val authorizedKey = keystoreManager.getPublicKeySSH(keyId)!!
        val (keyType, encoded) = authorizedKey.split(" ", limit = 2)
        val blob = readSshBlob(Base64.getDecoder().decode(encoded))

        assertEquals("ssh-rsa", keyType)
        assertEquals("ssh-rsa", String(blob[0], Charsets.UTF_8))
        assertEquals("public exponent 65537", listOf<Byte>(0x01, 0x00, 0x01), blob[1].toList())
        assertTrue("2048-bit modulus", blob[2].size >= 256)
    }

    @Test
    fun returnsNoSshKeyForAnUnknownIdentifier() {
        assertNull(keystoreManager.getPublicKeySSH("missing-${System.nanoTime()}"))
    }

    /** Splits an SSH blob into its length-prefixed fields. */
    private fun readSshBlob(blob: ByteArray): List<ByteArray> {
        val input = DataInputStream(ByteArrayInputStream(blob))
        val fields = mutableListOf<ByteArray>()
        while (input.available() > 0) {
            val field = ByteArray(input.readInt())
            input.readFully(field)
            fields.add(field)
        }
        return fields
    }

    // ----------------------------------------------------------- enumeration

    @Test
    fun listsKeysFromBothNamespacesWithTheirPrefixesStripped() {
        val credentialId = credentialKey("listing")
        val (keyId, _) = generalKey("ES256", "listing")

        val all = keystoreManager.listAllKeys()

        assertTrue(all.contains(credentialId))
        assertTrue(all.contains(keyId))
        assertTrue("prefixes must be stripped", all.none { it.startsWith("xkey_") })
    }

    @Test
    fun listsOnlyCredentialsInTheFido2Enumeration() {
        val credentialId = credentialKey("credential-listing")
        val (keyId, _) = generalKey("ES256", "credential-listing")

        val credentials = keystoreManager.listCredentials()

        assertTrue(credentials.contains(credentialId))
        assertFalse(credentials.contains(keyId))
    }

    @Test
    fun listsEveryRawKeystoreAlias() {
        val alias = rawKeystoreAlias("listing")

        assertTrue(keystoreManager.listAllKeystoreAliases().contains(alias))
    }

    // -------------------------------------------------------------- deletion

    @Test
    fun deletesByRawAliasOnlyOnce() {
        val alias = rawKeystoreAlias("delete")

        assertTrue(keystoreManager.deleteByAlias(alias))
        assertFalse(keystoreManager.deleteByAlias(alias))
        assertFalse(keyStore.containsAlias(alias))
    }

    @Test
    fun deletesAGeneralKeyOnlyOnce() {
        val (keyId, _) = generalKey("ES256", "delete")

        assertTrue(keystoreManager.generalKeyExists(keyId))
        assertTrue(keystoreManager.deleteGeneralKey(keyId))
        assertFalse(keystoreManager.generalKeyExists(keyId))
        assertFalse(keystoreManager.deleteGeneralKey(keyId))
    }

    @Test
    fun deletingAGeneralKeyLeavesTheCredentialNamespaceAlone() {
        val sharedId = "shared-delete-${System.nanoTime()}"
        credentialIds.add(sharedId)
        generalKeyIds.add(sharedId)
        runBlocking {
            keystoreManager.generateKeyForAlgorithm(sharedId, "ES256", -1, false)
            keystoreManager.generateKey(sharedId, requireBiometric = false)
        }

        assertTrue(keystoreManager.deleteGeneralKey(sharedId))
        assertTrue(keystoreManager.keyExists(sharedId))
    }

    // ----------------------------------------------------------- attestation

    @Test
    fun attestsAGeneralKeyThroughItsResolvedAlias() {
        val (keyId, _) = generalKey("ES256", "attestation")

        val chain = keystoreManager.getAttestationChain(keyId)

        assertNotNull(chain)
        assertTrue(chain!!.isNotEmpty())
    }

    @Test
    fun returnsNoAttestationChainForAnUnknownIdentifier() {
        assertNull(keystoreManager.getAttestationChain("missing-${System.nanoTime()}"))
    }

    @Test
    fun attestsWithACallerSuppliedChallengeAndLeavesNoKeyBehind() {
        val keyId = "attest-${System.nanoTime()}"
        val challenge = ByteArray(32) { it.toByte() }

        val chain = keystoreManager.getKeyAttestationWithChallenge(keyId, challenge)

        assertNotNull(chain)
        assertTrue(chain!!.isNotEmpty())
        assertTrue(
            "the ephemeral attestation key must not survive",
            keyStore.aliases().toList().none { it.startsWith("xkey_attest_$keyId") }
        )
    }

    @Test
    fun generatesAnAttestedKeyTheCallerOwnsTheCleanupFor() {
        val keyId = newGeneralKeyId("attested")

        val chain = keystoreManager.generateKeyWithAttestationChallenge(keyId, ByteArray(16) { 7 })

        assertNotNull(chain)
        assertTrue(chain!!.isNotEmpty())
        assertTrue("the key is deliberately left for the caller", keystoreManager.generalKeyExists(keyId))
    }

    @Test
    fun reportsStrongBoxBackingConsistentlyWithHardwareAvailability() {
        val credentialId = credentialKey("strongbox")

        assertEquals(
            keystoreManager.isStrongBoxAvailable(),
            keystoreManager.isKeyStrongBoxBacked(credentialId)
        )
        assertFalse(keystoreManager.isKeyStrongBoxBacked("missing-${System.nanoTime()}"))
    }

    // -------------------------------------------------- credential lifecycle

    @Test
    fun generatesACredentialWithAuthenticationDisabled() {
        val credentialId = newCredentialId("auth-duration")

        val cose = runBlocking {
            keystoreManager.generateKeyWithAuthDuration(credentialId, authDurationSeconds = -1)
        }

        assertTrue(cose.isNotEmpty())
        assertTrue(keystoreManager.keyExists(credentialId))
        assertNotNull(keystoreManager.getPublicKey(credentialId))
    }

    @Test
    fun refusesToRequireStrongBoxWhenTheDeviceHasNone() {
        val credentialId = newCredentialId("strongbox-required")

        if (keystoreManager.isStrongBoxAvailable()) {
            // A device with StrongBox must simply honour the request.
            assertTrue(
                runBlocking {
                    keystoreManager.generateKeyWithAuthDuration(credentialId, -1, requireStrongBox = true)
                }.isNotEmpty()
            )
            return
        }

        assertThrows(StrongBoxUnavailableException::class.java) {
            runBlocking {
                keystoreManager.generateKeyWithAuthDuration(credentialId, -1, requireStrongBox = true)
            }
        }
        assertFalse(keystoreManager.keyExists(credentialId))
    }

    @Test
    fun ed25519KeysLiveOutsideTheAndroidKeystore() {
        val keyId = newGeneralKeyId("ed25519")

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            assertThrows(UnsupportedAlgorithmException::class.java) {
                runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "Ed25519", -1, false) }
            }
            return
        }

        val der = try {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "Ed25519", -1, false) }
        } catch (e: KeyGenerationException) {
            // Ed25519 is a JCE provider capability, not a Keystore one. A device
            // without it must fail cleanly rather than leave a half-made key.
            assertFalse(keystoreManager.generalKeyExists(keyId))
            return
        }

        assertTrue(der.isNotEmpty())
        assertFalse("no Keystore entry is created for Ed25519", keystoreManager.generalKeyExists(keyId))
        assertEquals(
            "the raw identifier is what resolves for a software-backed key",
            keyId,
            keystoreManager.resolveKeystoreAlias(keyId)
        )
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    }
}

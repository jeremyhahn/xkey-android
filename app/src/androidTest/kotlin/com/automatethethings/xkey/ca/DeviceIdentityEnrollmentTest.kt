/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ca

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date

/**
 * The enrollment state machine behind [DeviceIdentity]: which Keystore aliases
 * and preferences each step leaves behind, what a refused step must not touch,
 * and how generations advance. [DeviceIdentityTest] covers what a request and
 * a stored credential carry; this class covers the state between them.
 *
 * Every case starts and ends with [DeviceIdentity.reset], which removes every
 * identity alias and preference; the one alias outside the identity prefix a
 * case creates is deleted in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class DeviceIdentityEnrollmentTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private lateinit var identity: DeviceIdentity

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        identity = DeviceIdentity(context)
        identity.reset()
    }

    @After
    fun tearDown() {
        identity.reset()
        if (keyStore.containsAlias(UNRELATED_ALIAS)) keyStore.deleteEntry(UNRELATED_ALIAS)
    }

    // -----------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------

    @Test
    fun anEmptyChallenge_mintsNoKeyAndLeavesNothingPending() {
        assertThrows(IllegalArgumentException::class.java) {
            identity.createEnrollmentRequest(ByteArray(0))
        }

        assertTrue("a refused request mints no identity key", identityAliases().isEmpty())
        val error = assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(softwareKeyPair(), "CN=After Empty"))
        }
        assertTrue(error.message!!.contains("No enrollment is pending"))
    }

    @Test
    fun aPendingRequest_onAFreshDevice_enrollsNothing() {
        identity.createEnrollmentRequest("pending".toByteArray())

        assertNull("a pending key is not the active identity", identity.activeAlias())
        assertNull(identity.credential())
        assertFalse(identity.isEnrolled())
        assertEquals("the pending key is in the Keystore", 1, identityAliases().size)
    }

    @Test
    fun aPendingRequest_leavesTheActiveIdentityAlone() {
        enroll("first")
        val alias = identity.activeAlias()
        val credential = identity.credential()!!.encoded

        identity.createEnrollmentRequest("second".toByteArray())

        assertEquals("a pending request does not move the generation", alias, identity.activeAlias())
        assertArrayEquals(credential, identity.credential()!!.encoded)
        assertTrue(identity.isEnrolled())
        assertTrue("the active key keeps serving", keyStore.containsAlias(alias))
    }

    @Test
    fun theSecurityLevel_isTheOneTheLeafAttests() {
        val request = identity.createEnrollmentRequest("level".toByteArray())
        val leaf = decode(request.attestationChain.first())

        val expected = when (attestationSecurityLevelOf(leaf)) {
            1 -> DeviceIdentity.LEVEL_TEE
            2 -> DeviceIdentity.LEVEL_STRONGBOX
            else -> DeviceIdentity.LEVEL_SOFTWARE
        }
        assertEquals(expected, request.securityLevel)
    }

    // -----------------------------------------------------------------
    // Refused stores
    // -----------------------------------------------------------------

    @Test
    fun storingWithNoPendingRequest_leavesAnEnrolledIdentityUntouched() {
        val issued = enroll("first")
        val before = snapshot()

        // The pending request was consumed by the first store; the same
        // certificate offered again has nothing to promote.
        val error = assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(issued)
        }
        assertTrue(error.message!!.contains("No enrollment is pending"))
        assertEquals(before, snapshot())
    }

    @Test
    fun storingACertificateForADifferentKey_leavesTheIdentityAndThePendingRequest() {
        enroll("first")
        val before = snapshot()
        val pending = identity.createEnrollmentRequest("second".toByteArray())

        assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(softwareKeyPair(), "CN=Wrong Key"))
        }
        assertEquals("a refused store changes nothing", before, snapshot())

        // The refusal does not cancel the request: the right certificate still lands.
        val issued = issueFor(pending, "CN=Second CA")
        identity.storeCredential(issued)
        assertArrayEquals(issued.encoded, identity.credential()!!.encoded)
    }

    @Test
    fun aRequestAfterAFailedStore_leavesTheEarlierKeyUnusable() {
        val stale = identity.createEnrollmentRequest("first".toByteArray())
        assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(softwareKeyPair(), "CN=Wrong Key"))
        }

        val fresh = identity.createEnrollmentRequest("second".toByteArray())
        assertNotEquals(
            "the retry mints a new key",
            PKCS10CertificationRequest(stale.csr).subjectPublicKeyInfo,
            PKCS10CertificationRequest(fresh.csr).subjectPublicKeyInfo
        )

        val error = assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(issueFor(stale, "CN=Stale CA"))
        }
        assertTrue(
            "a certificate for the abandoned key is not the pending one: ${error.message}",
            error.message!!.contains("does not certify")
        )
        assertNull(identity.activeAlias())

        identity.storeCredential(issueFor(fresh, "CN=Fresh CA"))
        val active = keyStore.getCertificate(identity.activeAlias())
        assertEquals(
            "the active key is the one the second request minted",
            PKCS10CertificationRequest(fresh.csr).subjectPublicKeyInfo,
            SubjectPublicKeyInfo.getInstance(active.publicKey.encoded)
        )
    }

    // -----------------------------------------------------------------
    // Generations
    // -----------------------------------------------------------------

    @Test
    fun aSuccessfulStore_retiresThePreviousGenerationAndAdvancesIt() {
        enroll("first")
        val previous = identity.activeAlias()!!

        val issued = enroll("second")
        val current = identity.activeAlias()!!

        assertNotEquals(previous, current)
        assertTrue(
            "the generation moves forward",
            generationOf(current) > generationOf(previous)
        )
        assertFalse("the retired key is deleted", keyStore.containsAlias(previous))
        assertTrue(keyStore.containsAlias(current))
        assertArrayEquals(issued.encoded, identity.credential()!!.encoded)
        assertTrue(identity.isEnrolled())
    }

    // -----------------------------------------------------------------
    // Expiry and chain
    // -----------------------------------------------------------------

    @Test
    fun theCredentialIsCurrentBeforeNotAfterAndExpiredPastIt() {
        val issued = enroll("expiry")
        val notAfter = issued.notAfter.time

        assertFalse(identity.isCredentialExpired(now = notAfter - 1))
        assertTrue(identity.isCredentialExpired(now = notAfter + 1))
    }

    /**
     * notAfter is inclusive (RFC 5280 §4.1.2.5): the certificate is valid at
     * that instant, and [X509Certificate.checkValidity] agrees. The device must
     * not call itself expired a moment before the CA does.
     */
    @Test
    fun theCredentialIsCurrentAtNotAfter() {
        val issued = enroll("boundary")
        val notAfter = issued.notAfter

        issued.checkValidity(notAfter)
        assertFalse(
            "a credential is still valid at its notAfter",
            identity.isCredentialExpired(now = notAfter.time)
        )
    }

    @Test
    fun theCredentialChain_keepsTheOrderItWasGiven() {
        val request = identity.createEnrollmentRequest("chain".toByteArray())
        val rootKey = softwareKeyPair()
        val root = selfSigned(rootKey, "CN=Order Root")
        val intermediateKey = softwareKeyPair()
        val intermediate = issue(intermediateKey.public, X500Name("CN=Order Intermediate"), "CN=Order Root", rootKey)
        val leaf = issueFor(request, "CN=Order Intermediate", issuerKey = intermediateKey)

        identity.storeCredential(leaf, listOf(intermediate, root))

        assertEquals(
            "issuer first, root last",
            listOf(intermediate.subjectX500Principal, root.subjectX500Principal),
            identity.credentialChain().map { it.subjectX500Principal }
        )
        assertArrayEquals(intermediate.encoded, identity.credentialChain()[0].encoded)
        assertArrayEquals(root.encoded, identity.credentialChain()[1].encoded)
    }

    @Test
    fun aCredentialStoredWithNoChain_hasAnEmptyChain() {
        enroll("no chain")
        assertTrue(identity.credentialChain().isEmpty())
    }

    // -----------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------

    @Test
    fun reset_removesEveryIdentityKeyAndPreference() {
        val issuerKey = softwareKeyPair()
        val request = identity.createEnrollmentRequest("first".toByteArray())
        identity.storeCredential(
            issueFor(request, "CN=Reset CA", issuerKey = issuerKey),
            listOf(selfSigned(issuerKey, "CN=Reset CA"))
        )
        identity.createEnrollmentRequest("abandoned".toByteArray())
        identity.createEnrollmentRequest("pending".toByteArray())
        assertEquals("precondition: active, abandoned and pending keys", 3, identityAliases().size)

        identity.reset()

        assertTrue("no identity key survives", identityAliases().isEmpty())
        assertTrue(
            "no identity preference survives",
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).all.isEmpty()
        )
        assertNull(identity.activeAlias())
        assertNull(identity.credential())
        assertTrue(identity.credentialChain().isEmpty())
        assertFalse(identity.isEnrolled())
        assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(softwareKeyPair(), "CN=After Reset"))
        }
    }

    @Test
    fun reset_leavesKeysOutsideTheIdentityPrefix() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(
                KeyGenParameterSpec.Builder(UNRELATED_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generateKeyPair()
        }
        enroll("first")

        identity.reset()

        assertTrue("reset touches only identity keys", keyStore.containsAlias(UNRELATED_ALIAS))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Requests, issues and stores a credential; returns the certificate. */
    private fun enroll(challenge: String): X509Certificate {
        val request = identity.createEnrollmentRequest(challenge.toByteArray())
        return issueFor(request, "CN=$challenge CA").also { identity.storeCredential(it) }
    }

    /** What a refused step must leave exactly as it was. */
    private data class Snapshot(
        val activeAlias: String?,
        val activeKeyPresent: Boolean,
        val credential: String?,
        val chain: List<String>,
        val enrolled: Boolean,
    )

    private fun snapshot(): Snapshot {
        val alias = identity.activeAlias()
        return Snapshot(
            activeAlias = alias,
            activeKeyPresent = alias != null && keyStore.containsAlias(alias),
            credential = identity.credential()?.encoded?.let(::hex),
            chain = identity.credentialChain().map { hex(it.encoded) },
            enrolled = identity.isEnrolled(),
        )
    }

    private fun identityAliases(): List<String> =
        keyStore.aliases().toList().filter { it.startsWith(DeviceIdentity.ALIAS_PREFIX) }

    private fun generationOf(alias: String): Int =
        alias.removePrefix(DeviceIdentity.ALIAS_PREFIX).toInt()

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun decode(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun softwareKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    /** Issues a certificate over the CSR's key, as a real CA would. */
    private fun issueFor(
        request: DeviceEnrollmentRequest,
        issuerName: String,
        issuerKey: KeyPair = softwareKeyPair(),
    ): X509Certificate {
        val csr = PKCS10CertificationRequest(request.csr)
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(csr.subjectPublicKeyInfo.encoded))
        return issue(publicKey, csr.subject, issuerName, issuerKey)
    }

    private fun issue(
        publicKey: java.security.PublicKey,
        subject: X500Name,
        issuerName: String,
        issuerKey: KeyPair,
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuerName),
            BigInteger.valueOf(System.nanoTime()),
            Date(now - ONE_DAY),
            Date(now + ONE_DAY),
            subject,
            publicKey
        )
        return JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder(SIG_ALG).build(issuerKey.private))
        )
    }

    private fun selfSigned(keyPair: KeyPair, subject: String): X509Certificate =
        issue(keyPair.public, X500Name(subject), subject, keyPair)

    /**
     * `attestationSecurityLevel`, the second field of the KeyDescription
     * SEQUENCE inside the attestation extension, read independently of
     * [DeviceIdentity]'s own parser.
     */
    private fun attestationSecurityLevelOf(leaf: X509Certificate): Int? {
        val extension = leaf.getExtensionValue(KEY_DESCRIPTION_OID) ?: return null
        val description = org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).octets
        val sequence = org.bouncycastle.asn1.ASN1Sequence.getInstance(description)
        return org.bouncycastle.asn1.ASN1Enumerated.getInstance(sequence.getObjectAt(1)).value.toInt()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PREFS_NAME = "xkey_device_identity"
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
        const val UNRELATED_ALIAS = "cv343_unrelated_test_key"
        const val SIG_ALG = "SHA256withECDSA"
        const val ONE_DAY = 24L * 60 * 60 * 1000
    }
}

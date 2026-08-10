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

package com.automatethethings.xkey.protocol

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * The Android Key Attestation DER reader inside [RequestHandler].
 *
 * `local.attestKey` and `local.attestDevice` report a security level and a
 * verified-boot state to the desktop, which the desktop then stores as the
 * device's attested posture. Those values come from a hand-rolled DER walk over
 * the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) rather than from a
 * parser library, and the emulator only ever produces one shape of extension —
 * so `ProtocolIntegrationTest` exercised a single path through it and the
 * RootOfTrust reader never ran at all.
 *
 * These tests hand the parser certificates carrying synthesised extensions,
 * covering the encodings a real device emits (ENUMERATED and INTEGER security
 * levels, RootOfTrust with and without the optional `verifiedBootHash`,
 * unrelated elements before it in `teeEnforced`) and the malformed input it
 * must survive rather than propagate.
 *
 * The parsing entry points are private, so they are reached reflectively: they
 * are pure DER logic with no other caller that a test can steer, and the
 * alternative is leaving the whole reader untested. Nothing here touches the
 * Keystore, the database or the network, and nothing is persisted.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerAttestationParsingTest {

    private lateinit var handler: RequestHandler

    /** Attestation OID the parser looks the extension up under. */
    private val attestationOid = "1.3.6.1.4.1.11129.2.1.17"

    @Before
    fun setUp() {
        val context: Context = ApplicationProvider.getApplicationContext()
        handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = SessionAuthManager()
        )
    }

    // ------------------------------------------------------------------
    // Security level
    // ------------------------------------------------------------------

    /**
     * The security level is what the desktop shows as "hardware" vs "software"
     * backing, so each of the three defined values must map to its own name.
     */
    @Test
    fun everyDefinedSecurityLevelIsDecoded() {
        assertEquals("software", securityLevelOf(extensionWithSecurityLevel(0, 0x0A)))
        assertEquals("tee", securityLevelOf(extensionWithSecurityLevel(1, 0x0A)))
        assertEquals("strongbox", securityLevelOf(extensionWithSecurityLevel(2, 0x0A)))
    }

    /** Some devices encode the level as INTEGER rather than ENUMERATED. */
    @Test
    fun anIntegerEncodedSecurityLevelIsAcceptedToo() {
        assertEquals("strongbox", securityLevelOf(extensionWithSecurityLevel(2, 0x02)))
        assertEquals("strongbox", parseExtension(certWith(extensionWithSecurityLevel(2, 0x02))).first)
    }

    /** An undefined level is not invented; the parser falls back. */
    @Test
    fun anUnknownSecurityLevelFallsBackToTheDeviceHeuristic() {
        assertIsFallback(securityLevelOf(extensionWithSecurityLevel(9, 0x0A)))
        assertIsFallback(parseExtension(certWith(extensionWithSecurityLevel(9, 0x0A))).first)
    }

    @Test
    fun aCertificateWithNoAttestationExtensionFallsBack() {
        assertIsFallback(securityLevelOf(null))
        assertIsFallback(parseExtension(certWith(null)).first)
    }

    /**
     * The extension value is an OCTET STRING wrapping the real DER. Anything
     * else is not an attestation extension.
     */
    @Test
    fun anExtensionThatIsNotWrappedInAnOctetStringFallsBack() {
        val notWrapped = tlv(0x30, tlv(0x02, byteArrayOf(1)))

        assertIsFallback(securityLevelOf(notWrapped))
        assertIsFallback(parseExtension(certWith(notWrapped)).first)
    }

    @Test
    fun anExtensionWhoseBodyIsNotASequenceFallsBack() {
        val notASequence = tlv(0x04, tlv(0x04, byteArrayOf(1, 2, 3)))

        assertIsFallback(securityLevelOf(notASequence))
        assertIsFallback(parseExtension(certWith(notASequence)).first)
    }

    @Test
    fun aTruncatedExtensionFallsBackInsteadOfThrowing() {
        val full = extensionWithSecurityLevel(2, 0x0A)
        val truncated = full.copyOfRange(0, full.size / 2)

        assertIsFallback(securityLevelOf(truncated))
        assertIsFallback(parseExtension(certWith(truncated)).first)
    }

    /**
     * A level field of the wrong ASN.1 type is not read as a level. Note that
     * `parseAttestationExtension` consumes the tag and length but not the
     * content of a field it rejects, which desynchronises the rest of the walk
     * — either way the answer is the device fallback, never a fabricated level.
     */
    @Test
    fun aMistypedSecurityLevelFieldIsHandledByBothReaders() {
        // 0x0C is UTF8String: neither ENUMERATED nor INTEGER.
        val mistyped = extensionWithSecurityLevel(2, 0x0C)

        assertIsFallback(securityLevelOf(mistyped))
        assertIsFallback(parseExtension(certWith(mistyped)).first)
    }

    // ------------------------------------------------------------------
    // RootOfTrust
    //
    // This suite found the reader unreachable: `parseRootOfTrust` matched a
    // context-specific constructed tag with `(tag and 0xC0) == 0xA0`, but
    // masking with 0xC0 clears the constructed bit 0x20, so the expression
    // yields one of 0x00/0x40/0x80/0xC0 and can never equal 0xA0. The mask is
    // now 0xE0.
    //
    // The consequence was not cosmetic: `local.attestDevice` reports
    // `bootState`, `deviceLocked`, `verifiedBootKey` and `verifiedBootHash` to
    // the desktop, and with the reader unreachable they were always the
    // hardcoded defaults — in particular `deviceLocked = true`, so an unlocked
    // bootloader attested as locked. These tests are the regression guard.
    // ------------------------------------------------------------------

    /**
     * A well-formed RootOfTrust — locked device, green boot state, both boot key
     * and boot hash present — is read out of the extension rather than replaced
     * by the defaults.
     */
    @Test
    fun aWellFormedRootOfTrustIsRead() {
        val bootKey = ByteArray(32) { (it + 1).toByte() }
        val bootHash = ByteArray(32) { (0xF0 - it).toByte() }
        val extension = extensionWith(
            securityLevel = 2,
            teeEnforced = tlv(0xA2, rootOfTrust(bootKey, true, 0, bootHash))
        )

        val (securityLevel, rootOfTrust) = parseExtension(certWith(extension))

        assertEquals("strongbox", securityLevel)
        assertEquals(0, intField(rootOfTrust, "bootState"))
        assertTrue(booleanField(rootOfTrust, "deviceLocked"))
        assertArrayEquals(bootKey, bytesField(rootOfTrust, "verifiedBootKey"))
        assertArrayEquals(bootHash, bytesField(rootOfTrust, "verifiedBootHash"))
    }

    /**
     * The security-relevant case: a device whose bootloader is unlocked and
     * whose boot state is not green must attest as such. Reporting the default
     * `deviceLocked = true` here is what the mask bug used to do.
     */
    @Test
    fun anUnlockedDeviceAttestsAsUnlocked() {
        val extension = extensionWith(
            securityLevel = 1,
            teeEnforced = tlv(0xA0, rootOfTrust(ByteArray(4), false, 2, null))
        )

        val rootOfTrust = parseExtension(certWith(extension)).second

        assertFalse(
            "an unlocked bootloader must not attest as locked",
            booleanField(rootOfTrust, "deviceLocked")
        )
        assertEquals(2, intField(rootOfTrust, "bootState"))
    }

    /**
     * `teeEnforced` is a bag of authorization tags, and the walk has to step
     * over every shape of element without losing its place: plain elements,
     * zero-length elements, and constructed context tags.
     */
    @Test
    fun theWalkStepsOverEveryShapeOfAuthorizationTag() {
        val teeEnforced =
            tlv(0x02, byteArrayOf(3)) +                    // a plain INTEGER tag
                tlv(0x05, ByteArray(0)) +                  // a zero-length element
                tlv(0xA5, ByteArray(8)) +                  // a context tag with content
                tlv(0xA0, byteArrayOf(0x02, 0x01, 0x01)) + // a context tag that is not a RootOfTrust
                tlv(0xA2, rootOfTrust(ByteArray(32) { 0x11 }, true, 0, null))

        val (securityLevel, rootOfTrust) = parseExtension(certWith(extensionWith(1, teeEnforced)))

        assertEquals("tee", securityLevel)
        // The walk reaches the trailing RootOfTrust and reads its 32-byte key,
        // which is the point: every preceding element shape was stepped over
        // without the reader losing its place.
        assertEquals(32, bytesField(rootOfTrust, "verifiedBootKey").size)
    }

    /**
     * A `teeEnforced` that is not a SEQUENCE stops the walk, but the security
     * level already read must still be reported.
     */
    @Test
    fun aMalformedTeeEnforcedStillYieldsTheSecurityLevel() {
        val extension = extensionWithRawTeeEnforced(2, tlv(0x04, ByteArray(8)))

        val (securityLevel, rootOfTrust) = parseExtension(certWith(extension))

        assertEquals("strongbox", securityLevel)
        assertEquals(0, intField(rootOfTrust, "bootState"))
        assertTrue(booleanField(rootOfTrust, "deviceLocked"))
        assertEquals(0, bytesField(rootOfTrust, "verifiedBootKey").size)
    }

    /** An empty `teeEnforced` leaves the defaults in place. */
    @Test
    fun anEmptyTeeEnforcedYieldsTheDefault() {
        val rootOfTrust = parseExtension(certWith(extensionWith(1, ByteArray(0)))).second

        assertEquals(0, intField(rootOfTrust, "bootState"))
        assertEquals(0, bytesField(rootOfTrust, "verifiedBootKey").size)
    }

    /**
     * A `teeEnforced` that ends mid-element must not propagate an EOF out of
     * the parser: `local.attestDevice` would fail outright rather than report a
     * degraded posture.
     */
    @Test
    fun aTeeEnforcedThatEndsMidElementIsAbsorbed() {
        // A tag with no length byte after it.
        val extension = extensionWith(1, byteArrayOf(0x02))

        val (securityLevel, rootOfTrust) = parseExtension(certWith(extension))

        assertEquals("tee", securityLevel)
        assertEquals(0, bytesField(rootOfTrust, "verifiedBootKey").size)
    }

    /** An element whose declared length overruns the buffer is also absorbed. */
    @Test
    fun anOverrunningElementLengthIsAbsorbed() {
        val extension = extensionWith(1, byteArrayOf(0xA2.toByte(), 0x7F))

        assertEquals(
            0,
            bytesField(parseExtension(certWith(extension)).second, "verifiedBootKey").size
        )
    }

    // ------------------------------------------------------------------
    // Reflection into the parser
    // ------------------------------------------------------------------

    private fun securityLevelOf(extensionValue: ByteArray?): String {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "parseAttestationSecurityLevel", X509Certificate::class.java
        )
        method.isAccessible = true
        return method.invoke(handler, certWith(extensionValue)) as String
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseExtension(cert: X509Certificate): Pair<String, Any> {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "parseAttestationExtension", X509Certificate::class.java
        )
        method.isAccessible = true
        return method.invoke(handler, cert) as Pair<String, Any>
    }

    private fun field(target: Any, name: String): Any {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        return field.get(target)!!
    }

    private fun intField(target: Any, name: String): Int = field(target, name) as Int

    private fun booleanField(target: Any, name: String): Boolean = field(target, name) as Boolean

    private fun bytesField(target: Any, name: String): ByteArray = field(target, name) as ByteArray

    /** StrongBox availability is device-dependent, so both fallbacks are valid. */
    private fun assertIsFallback(securityLevel: String) {
        assertTrue(
            "expected the StrongBox/TEE fallback, got $securityLevel",
            securityLevel == "tee" || securityLevel == "strongbox"
        )
    }

    // ------------------------------------------------------------------
    // DER fixtures
    // ------------------------------------------------------------------

    /** Wraps [content] in a DER tag-length-value triple. */
    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        when {
            content.size < 0x80 -> out.write(content.size)
            content.size < 0x100 -> {
                out.write(0x81)
                out.write(content.size)
            }
            else -> {
                out.write(0x82)
                out.write((content.size shr 8) and 0xFF)
                out.write(content.size and 0xFF)
            }
        }
        out.write(content)
        return out.toByteArray()
    }

    /** A `KeyDescription` carrying only a security level and an empty teeEnforced. */
    private fun extensionWithSecurityLevel(level: Int, levelTag: Int): ByteArray =
        keyDescription(level, levelTag, tlv(0x30, ByteArray(0)))

    /** A `KeyDescription` whose teeEnforced SEQUENCE holds [teeEnforced]. */
    private fun extensionWith(securityLevel: Int, teeEnforced: ByteArray): ByteArray =
        keyDescription(securityLevel, 0x0A, tlv(0x30, teeEnforced))

    /** A `KeyDescription` whose eighth element is [rawTeeEnforced] verbatim. */
    private fun extensionWithRawTeeEnforced(securityLevel: Int, rawTeeEnforced: ByteArray): ByteArray =
        keyDescription(securityLevel, 0x0A, rawTeeEnforced)

    /**
     * The `KeyDescription` SEQUENCE in the order the parser walks it:
     * attestationVersion, attestationSecurityLevel, keymasterVersion,
     * keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced,
     * teeEnforced — wrapped in the OCTET STRING an extension value carries.
     */
    private fun keyDescription(
        securityLevel: Int,
        securityLevelTag: Int,
        teeEnforcedElement: ByteArray
    ): ByteArray {
        val body = tlv(0x02, byteArrayOf(4)) +                             // attestationVersion
            tlv(securityLevelTag, byteArrayOf(securityLevel.toByte())) +   // attestationSecurityLevel
            tlv(0x02, byteArrayOf(4)) +                                    // keymasterVersion
            tlv(0x0A, byteArrayOf(1)) +                                    // keymasterSecurityLevel
            tlv(0x04, "challenge".toByteArray()) +                         // attestationChallenge
            tlv(0x04, ByteArray(0)) +                                      // uniqueId
            tlv(0x30, ByteArray(0)) +                                      // softwareEnforced
            teeEnforcedElement
        return tlv(0x04, tlv(0x30, body))
    }

    /** A RootOfTrust SEQUENCE; [bootHash] is omitted when null, as older versions do. */
    private fun rootOfTrust(
        verifiedBootKey: ByteArray,
        deviceLocked: Boolean,
        bootState: Int,
        bootHash: ByteArray?
    ): ByteArray {
        var body = tlv(0x04, verifiedBootKey) +
            tlv(0x01, byteArrayOf(if (deviceLocked) 0xFF.toByte() else 0x00)) +
            tlv(0x0A, byteArrayOf(bootState.toByte()))
        if (bootHash != null) {
            body += tlv(0x04, bootHash)
        }
        return tlv(0x30, body)
    }

    private fun certWith(extensionValue: ByteArray?): X509Certificate =
        FakeAttestationCertificate(attestationOid, extensionValue)
}

/**
 * A certificate that carries nothing but an attestation extension.
 *
 * The DER reader under test only ever calls `getExtensionValue`, so everything
 * else is inert. Building a real certificate with an arbitrary extension would
 * need a certificate builder the platform does not expose.
 */
private class FakeAttestationCertificate(
    private val oid: String,
    private val extensionValue: ByteArray?
) : X509Certificate() {

    override fun getExtensionValue(requestedOid: String?): ByteArray? =
        if (requestedOid == oid) extensionValue else null

    override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()

    override fun getNonCriticalExtensionOIDs(): MutableSet<String> =
        if (extensionValue != null) mutableSetOf(oid) else mutableSetOf()

    override fun hasUnsupportedCriticalExtension(): Boolean = false

    override fun checkValidity() = Unit

    override fun checkValidity(date: Date?) = Unit

    override fun getVersion(): Int = 3

    override fun getSerialNumber(): BigInteger = BigInteger.ONE

    @Suppress("DEPRECATION")
    override fun getIssuerDN(): java.security.Principal = X500Principal("CN=xKey Test")

    @Suppress("DEPRECATION")
    override fun getSubjectDN(): java.security.Principal = X500Principal("CN=xKey Test")

    override fun getNotBefore(): Date = Date(0)

    override fun getNotAfter(): Date = Date(Long.MAX_VALUE)

    override fun getTBSCertificate(): ByteArray = ByteArray(0)

    override fun getSignature(): ByteArray = ByteArray(0)

    override fun getSigAlgName(): String = "SHA256withECDSA"

    override fun getSigAlgOID(): String = "1.2.840.10045.4.3.2"

    override fun getSigAlgParams(): ByteArray? = null

    override fun getIssuerUniqueID(): BooleanArray? = null

    override fun getSubjectUniqueID(): BooleanArray? = null

    override fun getKeyUsage(): BooleanArray? = null

    override fun getBasicConstraints(): Int = -1

    override fun getEncoded(): ByteArray = ByteArray(0)

    override fun verify(key: PublicKey?) = Unit

    override fun verify(key: PublicKey?, sigProvider: String?) = Unit

    override fun toString(): String = "FakeAttestationCertificate"

    override fun getPublicKey(): PublicKey = throw UnsupportedOperationException("not needed")
}

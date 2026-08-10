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
package com.automatethethings.xkey.ui

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.entity.KeyEntity
import org.junit.After
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
 * Attestation-report rendering for [KeyDetailActivity].
 *
 * `KeyDetailActivityFlowTest.localAttestation_replacesPlaceholderWithReport`
 * runs a real Keystore attestation, but the emulator's chain carries an almost
 * empty `teeEnforced` authorization list: every optional row is skipped, the
 * whole element walk inside `parseTeeEnforcedList` never executes, and the
 * failure renderer has never run at all. This suite drives the two renderers
 * directly with hand-built DER so both the populated and the failed report are
 * covered without depending on what the device's Keymaster happens to emit.
 *
 * Both `displayLocalAttestationResult` and `showAttestationError` are private,
 * and neither is reachable from the UI on a device where attestation succeeds.
 * They are invoked reflectively on the main thread — the same technique
 * `SettingsFlowSupport` already uses to read `SettingsActivity.isInitializing`,
 * and the only way to assert the failure branch without changing production
 * code. The certificates handed in are inert stand-ins ([StubAttestationCert]):
 * the renderer only ever asks for the attestation extension, the subject
 * principal and the validity dates.
 *
 * ## A production bug this suite deliberately does not assert around
 *
 * Every multi-byte context tag (`BF xx yy`) in `parseTeeEnforcedList` computes
 * its content offset as `tagEnd + derLengthOffset(data, tagEnd)`, where
 * `tagEnd` already points at the length byte. `derLengthOffset` returns
 * *tag byte + length bytes*, so the result is one byte past the real content —
 * correct for the single-byte `0xAn` tags (which pass `pos + 1`), wrong for all
 * ten multi-byte ones. The rows therefore render with a decoded-from-garbage
 * value. This suite asserts that those rows *appear* (which is what proves the
 * branch ran) and asserts values only for the tags whose offset arithmetic is
 * right. See the suite report.
 */
@RunWith(AndroidJUnit4::class)
class KeyDetailAttestationReportTest {

    private val runId = System.nanoTime()

    private lateinit var context: Context
    private lateinit var scenario: ActivityScenario<KeyDetailActivity>

    private val seededKeyIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = keyTestContext()
        val key = KeyEntity(
            keyId = "attest-report-$runId",
            keyType = "signing",
            algorithm = "ES256",
            label = "Attestation Report $runId",
            // Deliberately not 256: the General card renders its own "Key Size"
            // row, and a differing value is what tells the two rows apart.
            keySizeBits = 384,
            source = "local"
        )
        seedKeyRow(key)
        seededKeyIds.add(key.keyId)
        // The attestation card owns the layout both renderers write into, so it
        // has to exist before either can be invoked. Its placeholder is the
        // cheapest proof that it does.
        scenario = launchKeyDetail(key.keyId)
        awaitText(scenario, context.getString(R.string.attest_no_attestation_yet))
    }

    @After
    fun tearDown() {
        scenario.close()
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
    }

    // ---------------------------------------------------------------
    // The populated report
    // ---------------------------------------------------------------

    /**
     * A chain whose leaf carries a fully-populated authorization list renders
     * the verified badge, all four overview rows and every section header.
     */
    @Test
    fun aPopulatedAttestation_rendersTheVerifiedBadgeAndEveryOverviewRow() {
        displayResult(chainOf(3, richExtension()), CHALLENGE.toByteArray())

        awaitText(scenario, context.getString(R.string.attest_verified))
        awaitText(scenario, "Attestation Overview")
        awaitText(scenario, "Key Properties")
        awaitText(scenario, "Device State")
        awaitText(scenario, "Certificate Chain")

        awaitText(scenario, context.getString(R.string.attest_security_level))
        awaitText(scenario, context.getString(R.string.attest_chain_count, 3))
        awaitText(scenario, context.getString(R.string.attest_version))
        awaitText(scenario, context.getString(R.string.attest_keymaster_version))
        awaitText(scenario, "Keymaster Security Level")

        // The placeholder is replaced, not appended to.
        awaitTextAbsent(scenario, context.getString(R.string.attest_no_attestation_yet))
    }

    /**
     * The single-byte authorization tags decode correctly, so their values are
     * asserted exactly.
     *
     * Unknown enum members fall through to the `Unknown(n)` arm of each lookup
     * table, which is the only thing that distinguishes a table miss from a
     * silently dropped field.
     */
    @Test
    fun singleByteAuthorizationTags_decodeIntoTheirKeyPropertyRows() {
        displayResult(chainOf(1, richExtension()), CHALLENGE.toByteArray())

        // The attestation list says 256 while the seeded row says 384, so this
        // cannot pass by hitting the General card's row of the same name.
        assertRowValue("Key Size", "256 bits")
        assertRowValue(
            "Purposes",
            "Encrypt, Decrypt, Sign, Verify, Derive Key, Wrap Key, Unknown(9)"
        )
        assertRowValue("Algorithm", "EC")
        assertRowValue("Digest", "SHA-256, SHA-512")
        assertRowValue("Padding", "RSA-PSS, PKCS7")
        assertRowValue("EC Curve", "P-256")
    }

    /**
     * The three value-less multi-byte tags only flip a boolean, so they are the
     * multi-byte tags whose rendered value is trustworthy.
     *
     * "Rollback Resistant" is not even added unless the flag parsed true, so its
     * presence alone is the assertion.
     */
    @Test
    fun valuelessMultiByteTags_renderAsYes() {
        displayResult(chainOf(1, richExtension()), CHALLENGE.toByteArray())

        val yes = context.getString(R.string.key_detail_yes)
        assertRowValue("No Auth Required", yes)
        assertRowValue("All Applications", yes)
        assertRowValue("Rollback Resistant", yes)
    }

    /**
     * The value-carrying multi-byte tags each add their row.
     *
     * Only presence is asserted: see the class KDoc for why the decoded values
     * are not trustworthy today.
     */
    @Test
    fun valueCarryingMultiByteTags_eachAddTheirRow() {
        displayResult(chainOf(1, richExtension()), CHALLENGE.toByteArray())

        listOf(
            "User Auth Type",
            "Auth Timeout",
            "Creation Date",
            "Origin",
            "OS Version",
            "OS Patch Level",
            "Vendor Patch Level",
            "Boot Patch Level"
        ).forEach { awaitText(scenario, it) }
    }

    /** A challenge that matches the nonce reports "Yes"; a mismatch reports "No". */
    @Test
    fun nonceComparison_reportsBothOutcomes() {
        displayResult(chainOf(1, richExtension()), CHALLENGE.toByteArray())
        awaitText(scenario, context.getString(R.string.attest_nonce_match))
        assertRowValue(context.getString(R.string.attest_nonce_match), context.getString(R.string.key_detail_yes))

        displayResult(chainOf(1, richExtension()), "a different nonce".toByteArray())
        assertRowValue(context.getString(R.string.attest_nonce_match), context.getString(R.string.key_detail_no))
    }

    /**
     * A three-certificate chain labels its members leaf / intermediate / root,
     * and a subject with no CN falls back to the raw distinguished name.
     */
    @Test
    fun theChainSection_labelsEveryPositionAndFallsBackToTheRawDn() {
        displayResult(chainOf(3, richExtension()), CHALLENGE.toByteArray())

        awaitText(scenario, "Leaf (Attestation)")
        awaitText(scenario, "Intermediate #1")
        awaitText(scenario, "Root")
        awaitText(scenario, "Valid")
        // Positions 1 and 2 carry no CN, so the renderer prints the whole DN.
        awaitText(scenario, NO_CN_DN)
        // Position 0 does, so only the common name is printed.
        awaitText(scenario, LEAF_CN)
    }

    // ---------------------------------------------------------------
    // Degraded extensions
    // ---------------------------------------------------------------

    /**
     * A leaf with no attestation extension falls back to the device heuristic.
     *
     * The emulator advertises no StrongBox, so the fallback is "TEE"; the
     * optional rows are all skipped because there is no extension to read.
     */
    @Test
    fun aLeafWithoutTheExtension_fallsBackToTheDeviceSecurityLevel() {
        displayResult(chainOf(1, null), CHALLENGE.toByteArray())

        awaitText(scenario, context.getString(R.string.attest_verified))
        assertRowValue(context.getString(R.string.attest_security_level), "TEE")
        // No extension means no authorization list at all.
        awaitTextAbsent(scenario, "Key Properties")
    }

    /**
     * An extension too short to hold a `KeyDescription`, one whose body is not a
     * SEQUENCE, and one whose declared lengths overrun all take the parser's
     * null exits rather than throwing.
     */
    @Test
    fun malformedExtensions_areAbsorbedIntoTheFallback() {
        listOf(
            // Too short to hold a KeyDescription at all.
            byteArrayOf(0x04, 0x01, 0x00),
            // Well-formed, but the wrapped element is not a SEQUENCE.
            tlv(0x04, tlv(0x04, ByteArray(8))),
            // A long-form length claiming four bytes that are not there, which
            // makes the copyOfRange throw rather than return.
            byteArrayOf(0x04, 0x84.toByte(), 0x00, 0x00, 0x00)
        ).forEach { extension ->
            displayResult(chainOf(1, extension), CHALLENGE.toByteArray())
            assertRowValue(context.getString(R.string.attest_security_level), "TEE")
        }
    }

    /**
     * A security level the lookup table does not know is reported verbatim
     * rather than swallowed, and a `KeyDescription` with no `teeEnforced`
     * element leaves every optional row out.
     */
    @Test
    fun anUnknownSecurityLevel_isReportedAndAnAbsentTeeListSkipsTheOptionalRows() {
        displayResult(chainOf(1, extensionWithoutTeeEnforced(securityLevel = 7)), CHALLENGE.toByteArray())

        assertRowValue(context.getString(R.string.attest_security_level), "Unknown (7)")
        awaitText(scenario, "Key Properties")
        awaitTextAbsent(scenario, "Purposes")
        awaitTextAbsent(scenario, "EC Curve")
    }

    /**
     * An authorization element whose declared length lies is skipped without
     * stopping the walk: the elements after it still render.
     */
    @Test
    fun anElementWithALyingLength_doesNotStopTheWalk() {
        val teeEnforced = tlv(0xA3, byteArrayOf(0x02, 0x7F)) +
            tlv(0xA2, tlv(0x02, byteArrayOf(3)))

        displayResult(chainOf(1, extensionWith(teeEnforced)), CHALLENGE.toByteArray())

        awaitText(scenario, "Algorithm")
        awaitText(scenario, "EC")
    }

    /**
     * An empty chain leaves the card blank rather than rendering a badge.
     *
     * The placeholder is cleared before the early return, so "nothing rendered"
     * is asserted on the card's own child count rather than on a text search.
     */
    @Test
    fun anEmptyChain_rendersNothingAtAll() {
        displayResult(emptyList(), CHALLENGE.toByteArray())

        awaitTextAbsent(scenario, context.getString(R.string.attest_no_attestation_yet))
        assertEquals(
            "An empty chain should leave the attestation card with no content",
            0,
            attestationCardChildCount()
        )
    }

    // ---------------------------------------------------------------
    // The failure renderer
    // ---------------------------------------------------------------

    /**
     * The failure renderer replaces the placeholder with the error badge and
     * the supplied message, and re-enables the button so the user can retry.
     *
     * Both messages the activity can pass are exercised: the "no chain" case
     * and the wrapped exception.
     */
    @Test
    fun attestationFailure_showsTheBadgeAndReEnablesTheButton() {
        showError(context.getString(R.string.attest_not_available))

        awaitText(scenario, context.getString(R.string.attest_failed))
        awaitText(scenario, context.getString(R.string.attest_not_available))
        awaitTextAbsent(scenario, context.getString(R.string.attest_no_attestation_yet))
        assertTrue(
            "The attest button should be usable again after a failure",
            attestButtonEnabled()
        )

        showError(context.getString(R.string.attest_error, "boom-$runId"))

        awaitText(scenario, "boom-$runId")
        // A second failure replaces the first rather than stacking.
        awaitTextAbsent(scenario, context.getString(R.string.attest_not_available))
    }

    /** A successful report after a failure clears the failure badge. */
    @Test
    fun aReportAfterAFailure_replacesTheFailureBadge() {
        showError(context.getString(R.string.attest_not_available))
        awaitText(scenario, context.getString(R.string.attest_failed))

        displayResult(chainOf(1, richExtension()), CHALLENGE.toByteArray())

        awaitText(scenario, context.getString(R.string.attest_verified))
        awaitTextAbsent(scenario, context.getString(R.string.attest_failed))
    }

    // ---------------------------------------------------------------
    // Reflection into the renderers
    // ---------------------------------------------------------------

    private fun displayResult(chain: List<X509Certificate>, nonce: ByteArray) {
        val method = KeyDetailActivity::class.java.getDeclaredMethod(
            "displayLocalAttestationResult",
            List::class.java,
            ByteArray::class.java
        ).apply { isAccessible = true }
        scenario.onActivity { method.invoke(it, chain, nonce) }
        waitForIdle()
    }

    private fun showError(message: String) {
        val method = KeyDetailActivity::class.java.getDeclaredMethod(
            "showAttestationError",
            String::class.java
        ).apply { isAccessible = true }
        scenario.onActivity { method.invoke(it, message) }
        waitForIdle()
    }

    private fun attestButtonEnabled(): Boolean {
        val field = KeyDetailActivity::class.java.getDeclaredField("attestButton")
            .apply { isAccessible = true }
        return withActivity(scenario) { (field.get(it) as View).isEnabled }
    }

    /** The number of views the attestation card currently holds. */
    private fun attestationCardChildCount(): Int {
        val field = KeyDetailActivity::class.java.getDeclaredField("attestationContentLayout")
            .apply { isAccessible = true }
        return withActivity(scenario) { (field.get(it) as ViewGroup).childCount }
    }

    /**
     * Asserts that some detail row labelled [label] carries [value].
     *
     * Rows are `[label][value]` inside their own container, so the value is a
     * sibling of the label rather than a child of it. *Every* matching label is
     * considered, not just the first: the General card renders its own "Key
     * Size" and "Algorithm" rows, so pinning to the first match would assert
     * against the wrong card.
     */
    private fun assertRowValue(label: String, value: String) {
        assertTrue(
            "Expected some '$label' row to read '$value'",
            awaitActivity(scenario) { activity ->
                collectViews(activity.window.decorView) {
                    it is TextView && it.text?.toString() == label
                }.any { labelView ->
                    val row = labelView.parent as? ViewGroup ?: return@any false
                    collectViews(row) {
                        it is TextView && it.text?.toString() == value
                    }.isNotEmpty()
                }
            }
        )
    }

    // ---------------------------------------------------------------
    // DER fixtures
    // ---------------------------------------------------------------

    /** Wraps [content] in a DER tag-length-value triple with a one-byte tag. */
    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        multiTagTlv(byteArrayOf(tag.toByte()), content)

    /** Wraps [content] behind an arbitrary-length DER tag. */
    private fun multiTagTlv(tag: ByteArray, content: ByteArray): ByteArray {
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

    /** A DER INTEGER holding [value], big-endian and minimally encoded. */
    private fun integer(value: Int): ByteArray {
        var remaining = value
        val bytes = mutableListOf<Byte>()
        do {
            bytes.add(0, (remaining and 0xFF).toByte())
            remaining = remaining ushr 8
        } while (remaining != 0)
        return tlv(0x02, bytes.toByteArray())
    }

    /** A DER SET of INTEGERs, as the purpose/digest/padding tags carry. */
    private fun integerSet(vararg values: Int): ByteArray =
        tlv(0x31, values.fold(ByteArray(0)) { acc, value -> acc + integer(value) })

    /**
     * The `KeyDescription` SEQUENCE in the order the parser walks it, wrapped in
     * the OCTET STRING that `getExtensionValue` returns.
     */
    private fun keyDescription(securityLevel: Int, teeEnforcedElement: ByteArray?): ByteArray {
        var body = integer(4) +                                   // attestationVersion
            tlv(0x0A, byteArrayOf(securityLevel.toByte())) +      // attestationSecurityLevel
            integer(4) +                                          // keymasterVersion
            tlv(0x0A, byteArrayOf(1)) +                           // keymasterSecurityLevel
            tlv(0x04, CHALLENGE.toByteArray()) +                  // attestationChallenge
            tlv(0x04, ByteArray(0)) +                             // uniqueId
            tlv(0x30, ByteArray(0))                               // softwareEnforced
        if (teeEnforcedElement != null) body += teeEnforcedElement
        return tlv(0x04, tlv(0x30, body))
    }

    /** An extension whose `teeEnforced` SEQUENCE holds [teeEnforced]. */
    private fun extensionWith(teeEnforced: ByteArray): ByteArray =
        keyDescription(1, tlv(0x30, teeEnforced))

    /** An extension with no eighth element at all. */
    private fun extensionWithoutTeeEnforced(securityLevel: Int): ByteArray =
        keyDescription(securityLevel, null)

    /**
     * An authorization list carrying one element of every shape the walk knows:
     * the six single-byte context tags, the three value-less multi-byte tags and
     * the eight value-carrying ones, plus a `RootOfTrust`.
     */
    private fun richExtension(): ByteArray {
        val teeEnforced =
            tlv(0xA1, integerSet(0, 1, 2, 3, 4, 5, 9)) +          // purposes (+ an unknown)
                tlv(0xA2, integer(3)) +                            // algorithm: EC
                tlv(0xA3, integer(256)) +                          // keySize
                tlv(0xA5, integerSet(4, 6)) +                      // digest
                tlv(0xA6, integerSet(3, 64)) +                     // padding
                tlv(0xAA, integer(1)) +                            // ecCurve: P-256
                multiTagTlv(TAG_ROLLBACK_RESISTANT, NULL_ELEMENT) +
                multiTagTlv(TAG_NO_AUTH_REQUIRED, NULL_ELEMENT) +
                multiTagTlv(TAG_USER_AUTH_TYPE, integer(2)) +
                multiTagTlv(TAG_AUTH_TIMEOUT, integer(30)) +
                multiTagTlv(TAG_ALL_APPLICATIONS, NULL_ELEMENT) +
                multiTagTlv(TAG_CREATION_DATE, tlv(0x02, CREATION_DATE_BYTES)) +
                multiTagTlv(TAG_ORIGIN, integer(0)) +
                multiTagTlv(TAG_ROOT_OF_TRUST, rootOfTrust()) +
                multiTagTlv(TAG_OS_VERSION, integer(140000)) +
                multiTagTlv(TAG_OS_PATCH_LEVEL, integer(202502)) +
                multiTagTlv(TAG_APPLICATION_ID, tlv(0x04, byteArrayOf(0xAB.toByte(), 0xCD.toByte()))) +
                multiTagTlv(TAG_VENDOR_PATCH_LEVEL, integer(202501)) +
                multiTagTlv(TAG_BOOT_PATCH_LEVEL, integer(202412))
        return extensionWith(teeEnforced)
    }

    /** A `RootOfTrust` SEQUENCE: boot key, locked flag, verified boot state. */
    private fun rootOfTrust(): ByteArray = tlv(
        0x30,
        tlv(0x04, ByteArray(32) { 0x11 }) +
            tlv(0x01, byteArrayOf(0xFF.toByte())) +
            tlv(0x0A, byteArrayOf(0))
    )

    /**
     * A chain of [size] certificates whose leaf carries [leafExtension].
     *
     * Only the leaf is ever parsed; the others exist so the chain section has
     * an intermediate and a root to label. They deliberately carry no CN so the
     * renderer's raw-DN fallback runs.
     */
    private fun chainOf(size: Int, leafExtension: ByteArray?): List<X509Certificate> =
        (0 until size).map { index ->
            StubAttestationCert(
                extensionValue = if (index == 0) leafExtension else null,
                subject = if (index == 0) X500Principal("CN=$LEAF_CN") else X500Principal(NO_CN_DN)
            )
        }

    private companion object {

        const val CHALLENGE = "xkey-attestation-challenge"
        const val LEAF_CN = "xKey Attestation Leaf"
        const val NO_CN_DN = "OU=xKey Attestation Chain"

        /** Context tag [303]: rollbackResistant. */
        val TAG_ROLLBACK_RESISTANT = byteArrayOf(0xBF.toByte(), 0x82.toByte(), 0x2F)

        /** Context tag [503]: noAuthRequired. */
        val TAG_NO_AUTH_REQUIRED = byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x77)

        /** Context tag [504]: userAuthType. */
        val TAG_USER_AUTH_TYPE = byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x78)

        /** Context tag [505]: authTimeout. */
        val TAG_AUTH_TIMEOUT = byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x79)

        /** Context tag [600]: allApplications. */
        val TAG_ALL_APPLICATIONS = byteArrayOf(0xBF.toByte(), 0x84.toByte(), 0x58)

        /** Context tag [701]: creationDateTime. */
        val TAG_CREATION_DATE = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x3D)

        /** Context tag [702]: origin. */
        val TAG_ORIGIN = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x3E)

        /** Context tag [704]: rootOfTrust. */
        val TAG_ROOT_OF_TRUST = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40)

        /** Context tag [705]: osVersion. */
        val TAG_OS_VERSION = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x41)

        /** Context tag [706]: osPatchLevel. */
        val TAG_OS_PATCH_LEVEL = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x42)

        /** Context tag [709]: attestationApplicationId. */
        val TAG_APPLICATION_ID = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x45)

        /** Context tag [718]: vendorPatchLevel. */
        val TAG_VENDOR_PATCH_LEVEL = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x4E)

        /** Context tag [719]: bootPatchLevel. */
        val TAG_BOOT_PATCH_LEVEL = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x4F)

        /** A DER NULL, which is what the value-less authorization tags carry. */
        val NULL_ELEMENT = byteArrayOf(0x05, 0x00)

        /** Eight bytes of epoch milliseconds, as a real creationDateTime holds. */
        val CREATION_DATE_BYTES = byteArrayOf(0, 0, 0x01, 0x8D.toByte(), 0x2E, 0x1A, 0x3C, 0x40)
    }
}

/**
 * A certificate that answers only what the attestation renderer asks of it.
 *
 * The renderer reads the attestation extension, the subject principal and the
 * two validity dates and nothing else; building a real certificate carrying an
 * arbitrary Keystore extension would need a certificate builder the platform
 * does not expose. `getSubjectX500Principal` has to be overridden explicitly —
 * its default implementation re-parses `getEncoded()`, which a stub cannot
 * supply.
 */
private class StubAttestationCert(
    private val extensionValue: ByteArray?,
    private val subject: X500Principal
) : X509Certificate() {

    override fun getExtensionValue(oid: String?): ByteArray? =
        if (oid == ATTESTATION_OID) extensionValue else null

    override fun getSubjectX500Principal(): X500Principal = subject

    override fun getIssuerX500Principal(): X500Principal = subject

    override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()

    override fun getNonCriticalExtensionOIDs(): MutableSet<String> =
        if (extensionValue != null) mutableSetOf(ATTESTATION_OID) else mutableSetOf()

    override fun hasUnsupportedCriticalExtension(): Boolean = false

    override fun checkValidity() = Unit

    override fun checkValidity(date: Date?) = Unit

    override fun getVersion(): Int = 3

    override fun getSerialNumber(): BigInteger = BigInteger.ONE

    @Suppress("DEPRECATION")
    override fun getIssuerDN(): java.security.Principal = subject

    @Suppress("DEPRECATION")
    override fun getSubjectDN(): java.security.Principal = subject

    override fun getNotBefore(): Date = Date(0)

    override fun getNotAfter(): Date = Date(FAR_FUTURE_MS)

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

    override fun toString(): String = "StubAttestationCert"

    override fun getPublicKey(): PublicKey = throw UnsupportedOperationException("not needed")

    private companion object {
        const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /** Year 2100-ish, so the rendered validity range is stable. */
        const val FAR_FUTURE_MS = 4_102_444_800_000L
    }
}

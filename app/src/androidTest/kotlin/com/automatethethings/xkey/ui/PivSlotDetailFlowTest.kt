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
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.Date

/**
 * Instrumented tests for the [PivSlotDetailActivity] actions.
 *
 * `PivSlotDetailActivityUiTest` asserts the screen's read-only content. This
 * suite drives everything that *does* something: the three clipboard exports,
 * a real signature against an Android Keystore key, the delete confirmation's
 * two outcomes, and the degraded renderings the screen has to survive — an
 * algorithm token it cannot map to a [PivAlgorithm], and certificate bytes that
 * are not a certificate.
 *
 * Slots are seeded per test (JUnit rebuilds the fixture for each), so the delete
 * test may consume its slot without affecting the others. Retired slots 9 and
 * 11-14 are used here; slots 19 and 20 belong to the read-only suite and the
 * primary slots to the protocol tests.
 *
 * Tests cover:
 * - Copying the public-key fingerprint, the public key DER and the certificate DER
 * - Signing test data with a real key, and the refusal when the algorithm token
 *   is not one the app knows
 * - Certificate card: expiring and expired badges, the parse-failure fallback,
 *   and the "no certificate" state
 * - Info card omitting the key size for an unmappable algorithm
 * - Delete: cancel keeps the slot, confirm clears it and finishes the screen
 *
 * Every slot row and Keystore alias is removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class PivSlotDetailFlowTest {

    private lateinit var dao: PivSlotDao
    private lateinit var keyManager: PivKeyManager
    private var publicKeyDer: ByteArray = ByteArray(0)
    private var expiredCertificateDer: ByteArray = ByteArray(0)

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).pivSlotDao()
        keyManager = PivKeyManager(dao)

        // A real Keystore key, so "Sign Test Data" exercises the signing path
        // rather than an error branch.
        runBlocking {
            keyManager.deleteKey(SIGNING_SLOT)
            keyManager.generateKey(SIGNING_SLOT, ALGORITHM)
            publicKeyDer = requireNotNull(dao.getBySlotId(SIGNING_SLOT.hexId)?.publicKeyDer)
        }

        val now = System.currentTimeMillis()
        val expiredCertificate = TestCertificates.selfSigned(
            alias = EXPIRED_ALIAS,
            commonName = EXPIRED_CN,
            notBefore = Date(now - 30L * TestCertificates.ONE_DAY_MS),
            notAfter = Date(now - TestCertificates.ONE_DAY_MS)
        )
        expiredCertificateDer = expiredCertificate.encoded
        val expiringCertificate = TestCertificates.selfSigned(
            alias = EXPIRING_ALIAS,
            commonName = EXPIRING_CN,
            notAfter = Date(now + 10L * TestCertificates.ONE_DAY_MS)
        )

        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = EXPIRED_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    publicKeyDer = expiredCertificate.publicKey.encoded,
                    certificateDer = expiredCertificateDer,
                    hasKey = true
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = EXPIRING_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    publicKeyDer = expiringCertificate.publicKey.encoded,
                    certificateDer = expiringCertificate.encoded,
                    hasKey = true
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = BROKEN_CERT_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    certificateDer = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00),
                    hasKey = true
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = UNKNOWN_ALGORITHM_SLOT.hexId,
                    algorithm = UNKNOWN_ALGORITHM,
                    publicKeyDer = expiringCertificate.publicKey.encoded,
                    hasKey = true
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            keyManager.deleteKey(SIGNING_SLOT)
            listOf(EXPIRED_SLOT, EXPIRING_SLOT, BROKEN_CERT_SLOT, UNKNOWN_ALGORITHM_SLOT)
                .forEach { dao.deleteBySlotId(it.hexId) }
        }
        listOf(EXPIRED_ALIAS, EXPIRING_ALIAS).forEach { TestCertificates.deleteAlias(it) }
    }

    // ---------------------------------------------------------------
    // Clipboard exports
    // ---------------------------------------------------------------

    @Test
    fun tappingTheFingerprint_copiesItAndConfirms() {
        val scenario = launch(SIGNING_SLOT)
        val fingerprint = sha256Fingerprint(publicKeyDer)
        assertTextInTree(scenario, fingerprint)

        clickTextInTree(scenario, fingerprint)

        assertEquals(fingerprint, DialogFlowSupport.clipboardText(scenario))
        assertShownTextInTree(scenario, withString(scenario, R.string.piv_fingerprint_copied))
    }

    @Test
    fun exportPublicKey_copiesTheDerAsHex() {
        val scenario = launch(SIGNING_SLOT)
        val exportLabel = withString(scenario, R.string.piv_detail_export_pubkey)
        assertTextInTree(scenario, exportLabel)

        clickTextInTree(scenario, exportLabel)

        assertEquals(publicKeyDer.toHex(), DialogFlowSupport.clipboardText(scenario))
        assertShownTextInTree(scenario, "Public key DER copied")
    }

    @Test
    fun exportCertificate_copiesTheDerAsHex() {
        val scenario = launch(EXPIRED_SLOT)
        val exportLabel = withString(scenario, R.string.piv_cert_export)
        assertTextInTree(scenario, exportLabel)

        clickTextInTree(scenario, exportLabel)

        assertEquals(expiredCertificateDer.toHex(), DialogFlowSupport.clipboardText(scenario))
        assertShownTextInTree(scenario, "Certificate DER copied")
    }

    // ---------------------------------------------------------------
    // Signing
    // ---------------------------------------------------------------

    /**
     * The emulator has no enrolled biometric, so the key is generated without
     * an authentication requirement and signing must succeed outright.
     */
    @Test
    fun signTestData_signsWithTheSlotKeyAndRecordsTheUse() {
        val scenario = launch(SIGNING_SLOT)
        val signLabel = withString(scenario, R.string.piv_action_sign_test)
        assertTextInTree(scenario, signLabel)
        val before = runBlocking { dao.getBySlotId(SIGNING_SLOT.hexId)!!.useCount }

        clickTextInTree(scenario, signLabel)

        assertTrue(
            "A successful signature should be confirmed on screen",
            awaitShownTextInTree(scenario, "Signature successful")
        )
        awaitCondition("Signing should record a use against the slot") {
            runBlocking { dao.getBySlotId(SIGNING_SLOT.hexId)!!.useCount } > before
        }
    }

    /** An algorithm token the app cannot map is refused before any Keystore call. */
    @Test
    fun signTestData_refusesAnUnknownAlgorithm() {
        val scenario = launch(UNKNOWN_ALGORITHM_SLOT)
        val signLabel = withString(scenario, R.string.piv_action_sign_test)
        assertTextInTree(scenario, signLabel)

        clickTextInTree(scenario, signLabel)

        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.piv_sign_test_error, "Unknown algorithm")
        )
    }

    // ---------------------------------------------------------------
    // Certificate card
    // ---------------------------------------------------------------

    @Test
    fun certificateCard_marksAnExpiredCertificate() {
        val scenario = launch(EXPIRED_SLOT)

        assertTextInTree(scenario, EXPIRED_CN)
        assertTextInTree(scenario, withString(scenario, R.string.piv_cert_expired))
    }

    @Test
    fun certificateCard_warnsAboutAnImminentExpiry() {
        val scenario = launch(EXPIRING_SLOT)

        assertTextInTree(scenario, EXPIRING_CN)
        assertTextInTree(scenario, withString(scenario, R.string.piv_cert_expiring))
    }

    /** Unparseable bytes must produce a message, not a crash or a blank card. */
    @Test
    fun certificateCard_reportsBytesItCannotParse() {
        val scenario = launch(BROKEN_CERT_SLOT)

        assertTextInTree(scenario, withString(scenario, R.string.piv_section_certificate))
        assertTextInTree(scenario, "Failed to parse certificate")
    }

    @Test
    fun certificateCard_reportsWhenNoCertificateHasBeenImported() {
        val scenario = launch(SIGNING_SLOT)

        assertTextInTree(scenario, withString(scenario, R.string.piv_no_certificate))
    }

    // ---------------------------------------------------------------
    // Info card
    // ---------------------------------------------------------------

    /**
     * An unmappable algorithm is echoed verbatim, and the key-size row — which
     * can only come from the enum — is left out entirely.
     */
    @Test
    fun infoCard_echoesAnUnknownAlgorithmAndOmitsTheKeySize() {
        val scenario = launch(UNKNOWN_ALGORITHM_SLOT)

        assertTextInTree(scenario, UNKNOWN_ALGORITHM)
        assertTextNotInTree(scenario, withString(scenario, R.string.piv_detail_key_size))
    }

    // ---------------------------------------------------------------
    // Delete
    // ---------------------------------------------------------------

    @Test
    fun delete_cancelled_keepsTheSlotPopulated() {
        val scenario = launch(SIGNING_SLOT)
        val deleteLabel = withString(scenario, R.string.piv_action_delete)
        assertTextInTree(scenario, deleteLabel)

        clickTextInTree(scenario, deleteLabel)
        // "Delete Key" is both piv_delete_title and piv_action_delete, so the
        // dialog carries it on its title *and* its positive button and a text
        // matcher is ambiguous even inside the dialog root. The message is
        // unique, so it is what identifies the confirmation.
        onView(withText(deleteMessage(scenario)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        DialogFlowSupport.clickButton(android.R.id.button2)
        waitForIdle()

        assertNotNull(
            "Cancelling the confirmation must keep the key",
            runBlocking { dao.getBySlotId(SIGNING_SLOT.hexId) }
        )
    }

    @Test
    fun delete_confirmed_clearsTheSlotAndFinishes() {
        val scenario = launch(SIGNING_SLOT)
        val deleteLabel = withString(scenario, R.string.piv_action_delete)
        assertTextInTree(scenario, deleteLabel)

        clickTextInTree(scenario, deleteLabel)
        // The dialog repeats "Delete Key" on its title and its positive button,
        // so the confirmation is clicked by button id rather than by label.
        DialogFlowSupport.clickButton(android.R.id.button1)

        awaitCondition("Confirming must clear the slot") {
            runBlocking { dao.getBySlotId(SIGNING_SLOT.hexId) } == null
        }
        assertNull(runBlocking { dao.getBySlotId(SIGNING_SLOT.hexId) })
        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(slot: PivSlot): ActivityScenario<PivSlotDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PivSlotDetailActivity::class.java
        ).apply {
            putExtra(PivSlotDetailActivity.EXTRA_SLOT_ID, slot.hexId)
        }
        val scenario = ActivityScenario.launch<PivSlotDetailActivity>(intent)
        assertTextInTree(scenario, slot.label)
        return scenario
    }

    private fun withString(
        scenario: ActivityScenario<PivSlotDetailActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    /** The delete confirmation's message, the one label unique to that dialog. */
    private fun deleteMessage(scenario: ActivityScenario<PivSlotDetailActivity>): String =
        withString(
            scenario,
            R.string.piv_delete_message,
            SIGNING_SLOT.hexId,
            SIGNING_SLOT.label
        )

    /** Mirrors the screen's colon-separated uppercase SHA-256 rendering. */
    private fun sha256Fingerprint(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(der)
            .joinToString(":") { "%02X".format(it) }

    /** Mirrors the screen's lowercase hex export. */
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        /** Retired slots left free by the other PIV suites. */
        val SIGNING_SLOT = PivSlot.RETIRED_9
        val EXPIRED_SLOT = PivSlot.RETIRED_11
        val EXPIRING_SLOT = PivSlot.RETIRED_12
        val BROKEN_CERT_SLOT = PivSlot.RETIRED_13
        val UNKNOWN_ALGORITHM_SLOT = PivSlot.RETIRED_14

        val ALGORITHM = PivAlgorithm.ES256

        /** Not a [PivAlgorithm] constant, so `valueOf` has to fail. */
        const val UNKNOWN_ALGORITHM = "ML-DSA-87"

        const val EXPIRED_ALIAS = "xkey_uitest_pivdetailflow_expired"
        const val EXPIRING_ALIAS = "xkey_uitest_pivdetailflow_expiring"
        const val EXPIRED_CN = "xKey Flow Expired Slot"
        const val EXPIRING_CN = "xKey Flow Expiring Slot"
    }
}

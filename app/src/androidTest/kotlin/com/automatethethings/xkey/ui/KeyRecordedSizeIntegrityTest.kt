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
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.Spinner
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Guards one invariant of [KeyManagementActivity]'s create flow: **the size
 * recorded against a key must describe the key that was actually produced.**
 *
 * The screen used to derive `keySizeBits` from the algorithm the dialog offered
 * rather than from the key the Keystore returned. Picking "RSA-OAEP 4096" wrote
 * `keySizeBits = 4096` while the generation call was hard-coded to "RS256",
 * which is 2048-bit — so the vault, the detail screen and anything reading the
 * row over the wire all reported a strength the key does not have.
 *
 * Every assertion here compares the stored size against the real bit length
 * decoded from the stored `publicKeyDer`, so the suite keeps passing if and when
 * the generation path is taught to honour 4096; it only fails if the row starts
 * lying again.
 *
 * The flow mechanics (seeded rows, the biometric switch, `KeyStoreSyncManager`
 * re-discovering stray aliases) are the same as `KeyManagementFlowTest`; see its
 * class KDoc for why each is necessary.
 */
@RunWith(AndroidJUnit4::class)
class KeyRecordedSizeIntegrityTest {

    private val runId = System.nanoTime()

    private lateinit var keyDao: KeyDao
    private lateinit var scenario: ActivityScenario<KeyManagementActivity>

    /** Key ids created through the UI during a test; cleaned up in @After. */
    private val createdKeyIds = mutableListOf<String>()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
        scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        waitForIdle()
    }

    @After
    fun tearDown() {
        if (this::scenario.isInitialized) {
            scenario.close()
        }
        runBlocking {
            for (keyId in createdKeyIds) {
                // The alias has to go first: a surviving alias is rediscovered by
                // KeyStoreSyncManager on the next launch and the row reappears.
                TestCertificates.deleteAlias(GENERAL_ALIAS_PREFIX + keyId)
                keyDao.deleteByKeyId(keyId)
            }
        }
        createdKeyIds.clear()
    }

    /**
     * The regression itself: asking for the 4096-bit OAEP option must not record
     * 4096 against a 2048-bit modulus.
     */
    @Test
    fun encryptionKey_recordsTheSizeOfTheKeyThatWasActuallyGenerated() {
        val key = createKey(
            "Size Integrity OAEP 4096 $runId",
            PURPOSE_ENCRYPTION,
            algorithmIndex = 1,
            timeoutMs = RSA_TIMEOUT_MS
        )

        assertEquals("RSA-OAEP-4096", key.algorithm)
        val der = key.publicKeyDer
        assertNotNull("An encryption key must record its public key", der)
        assertEquals(
            "The recorded size must be the modulus size of the generated key",
            actualSizeBits(der!!),
            key.keySizeBits
        )
    }

    /** The smaller OAEP option must be just as honest. */
    @Test
    fun encryptionKey_atTheDefaultOption_alsoMatchesItsModulus() {
        val key = createKey(
            "Size Integrity OAEP 2048 $runId",
            PURPOSE_ENCRYPTION,
            algorithmIndex = 0,
            timeoutMs = RSA_TIMEOUT_MS
        )

        assertEquals("RSA-OAEP-2048", key.algorithm)
        assertEquals(actualSizeBits(key.publicKeyDer!!), key.keySizeBits)
    }

    /**
     * The read-back must not regress the signing path, whose sizes were already
     * correct: an EC key's size is the field size of its curve.
     */
    @Test
    fun signingKey_recordsTheCurveFieldSize() {
        val key = createKey("Size Integrity ES384 $runId", PURPOSE_SIGNING, algorithmIndex = 1)

        assertEquals("ES384", key.algorithm)
        assertEquals(384, key.keySizeBits)
        assertEquals(actualSizeBits(key.publicKeyDer!!), key.keySizeBits)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Decodes an SPKI public key and returns its real strength in bits. */
    private fun actualSizeBits(der: ByteArray): Int {
        val spec = X509EncodedKeySpec(der)
        val publicKey = listOf("EC", "RSA").firstNotNullOfOrNull { name ->
            runCatching { KeyFactory.getInstance(name).generatePublic(spec) }.getOrNull()
        } ?: throw AssertionError("The stored public key could not be decoded")

        return when (publicKey) {
            is RSAPublicKey -> publicKey.modulus.bitLength()
            is ECPublicKey -> publicKey.params.curve.field.fieldSize
            else -> throw AssertionError("Unexpected key type ${publicKey.algorithm}")
        }
    }

    /** Runs the create flow and returns the row it produced. */
    private fun createKey(
        label: String,
        purposeIndex: Int,
        algorithmIndex: Int,
        timeoutMs: Long = CREATE_TIMEOUT_MS
    ): KeyEntity {
        val before = runBlocking { keyDao.getAll() }.map { it.keyId }.toSet()

        onView(nthMatch(allOf(withText(R.string.key_create_title), isDisplayed()), 0))
            .perform(click())
        waitForIdle()

        onView(isAssignableFrom(EditText::class.java))
            .inRoot(isDialog())
            .perform(replaceText(label), closeSoftKeyboard())
        selectSpinnerItem(PURPOSE_SPINNER, purposeIndex)
        selectSpinnerItem(ALGORITHM_SPINNER, algorithmIndex)
        // The emulator has no enrolled biometric, so an auth-bound key cannot be
        // generated there; the switch defaults to on and has to be cleared.
        onView(isAssignableFrom(MaterialSwitch::class.java))
            .inRoot(isDialog())
            .perform(setChecked(false))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        var created: KeyEntity? = null
        awaitCondition("A new key row should be created", timeoutMs) {
            created = runBlocking { keyDao.getAll() }.firstOrNull { it.keyId !in before }
            created != null
        }
        val key = created ?: throw AssertionError("No key row was created")
        createdKeyIds.add(key.keyId)
        return key
    }

    private fun selectSpinnerItem(spinnerIndex: Int, itemIndex: Int) {
        onView(nthMatch(isAssignableFrom(Spinner::class.java), spinnerIndex))
            .inRoot(isDialog())
            .perform(
                object : ViewAction {
                    override fun getConstraints(): Matcher<View> =
                        isAssignableFrom(Spinner::class.java)

                    override fun getDescription(): String = "select spinner item $itemIndex"

                    override fun perform(uiController: UiController, view: View) {
                        (view as Spinner).setSelection(itemIndex)
                        uiController.loopMainThreadUntilIdle()
                    }
                }
            )
        waitForIdle()
    }

    /**
     * Sets a compound button's state without injecting a tap: the switch sits at
     * the bottom of a dialog whose height depends on the device, and Espresso
     * refuses to click a partially obscured view.
     */
    private fun setChecked(checked: Boolean): ViewAction = object : ViewAction {
        override fun getConstraints(): Matcher<View> =
            isAssignableFrom(CompoundButton::class.java)

        override fun getDescription(): String = "set checked to $checked"

        override fun perform(uiController: UiController, view: View) {
            (view as CompoundButton).isChecked = checked
            uiController.loopMainThreadUntilIdle()
        }
    }

    private companion object {
        /** Alias prefix used by `KeystoreManager` for general-purpose keys. */
        const val GENERAL_ALIAS_PREFIX = "xkey_key_"

        const val PURPOSE_SPINNER = 0
        const val ALGORITHM_SPINNER = 1

        const val PURPOSE_SIGNING = 0
        const val PURPOSE_ENCRYPTION = 3

        /** EC key generation is quick; RSA on an emulator is not. */
        const val CREATE_TIMEOUT_MS = 20_000L
        const val RSA_TIMEOUT_MS = 90_000L
    }
}

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
package com.automatethethings.xkey.ui

import android.app.Application
import android.os.Looper
import android.view.View
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.widget.Spinner
import com.automatethethings.xkey.crypto.KeyPresence
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.testing.MainLooperWait
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.security.KeyStore

/**
 * #255 review r7: the co-sign screen's Generate QR listener read the selected
 * key's public key with no handler, so a key store that cannot be read
 * (here the software key store) threw out of the click listener and crashed
 * the app. The read now goes through the screen's refusing read: the screen
 * shows a refusal and draws no QR.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignInitiatorQrRefusalTest {

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    @Test
    fun generateQrWithAnUnreadableKeyStoreIsARefusalNotACrash() {
        val activity = started()

        val keystore = spyk(KeystoreManager(activity))
        every { keystore.ed25519Prefs() } returns null
        val software = mockk<SoftwareKeyStore>()
        every { software.presence(any()) } returns KeyPresence.UNREADABLE
        every { keystore.softwareKeys() } returns software
        set(activity, "keystoreManager", keystore)
        set(activity, "currentSignatureData", ContentAuthenticityData(contentHash = "00", signatures = emptyList()))
        set(activity, "signingKeyIds", listOf(KEY_ID))
        set(activity, "signingKeyTypes", listOf("signing"))
        set(activity, "signingKeyMaterials", listOf<ByteArray?>(null))
        val spinner = get(activity, "keySpinner") as Spinner
        spinner.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_item, listOf(KEY_ID))
        spinner.setSelection(0)

        val generate = CoSignActivity::class.java.getDeclaredMethod("generateInitiatorQR").apply { isAccessible = true }
        val failure = runCatching { generate.invoke(activity) }.exceptionOrNull()
        assertNull("Generate QR threw on an unreadable key store: ${failure?.cause ?: failure}", failure)

        val qr = get(activity, "qrImageView") as ImageView
        assertNotEquals("no QR is drawn for a key whose store cannot be read", View.VISIBLE, qr.visibility)
    }

    /**
     * #255 verify r3: a certificate read that fails (a key-store error, or
     * no public key) refuses the QR. The QR used to name the key id as its
     * owner in place of the key's fingerprint.
     */
    @Test
    fun aFailedCertificateReadRefusesTheQr() {
        for (failure in listOf<() -> ByteArray?>({ throw java.security.KeyStoreException("certificate") }, { null })) {
            val activity = initiator { keystore ->
                every { keystore.getPublicKeyDER(KEY_ID, any()) } answers { failure() }
            }
            val generate = CoSignActivity::class.java.getDeclaredMethod("generateInitiatorQR").apply { isAccessible = true }
            val thrown = runCatching { generate.invoke(activity) }.exceptionOrNull()
            assertNull("Generate QR threw on a failed certificate read: ${thrown?.cause ?: thrown}", thrown)

            val qr = get(activity, "qrImageView") as ImageView
            assertNotEquals("a QR was drawn without the owner's public key", View.VISIBLE, qr.visibility)
        }
    }

    /** A readable key's QR names the key's fingerprint as its owner, never its id. */
    @Test
    fun aReadableKeysQrNamesItsFingerprint() {
        val der = byteArrayOf(1, 2, 3)
        val payloads = mutableListOf<String>()
        io.mockk.mockkObject(com.automatethethings.xkey.qr.QrCodeGenerator)
        every { com.automatethethings.xkey.qr.QrCodeGenerator.generate(any(), any()) } answers {
            payloads += firstArg<String>()
            android.graphics.Bitmap.createBitmap(1, 1, android.graphics.Bitmap.Config.ARGB_8888)
        }
        val activity = initiator { keystore -> every { keystore.getPublicKeyDER(KEY_ID, any()) } returns der }
        CoSignActivity::class.java.getDeclaredMethod("generateInitiatorQR").apply { isAccessible = true }.invoke(activity)

        assertEquals(1, payloads.size)
        val fingerprint = com.automatethethings.xkey.media.MediaHasher.hashBytes(der)
        org.junit.Assert.assertTrue("the QR does not name the key's fingerprint", fingerprint in payloads[0])
        org.junit.Assert.assertFalse("the QR names the key id as its owner", KEY_ID in payloads[0])
    }

    /**
     * Bypass guard: every key read on the co-sign screen goes through the
     * screens' refusal choke point, and no co-sign QR falls back to the key
     * id for its owner.
     */
    @Test
    fun theCoSignScreenNeverNamesItsOwnerByKeyId() {
        val root = listOf(java.io.File("src/main/kotlin"), java.io.File("app/src/main/kotlin")).first { it.isDirectory }
        val source = java.io.File(root, "com/automatethethings/xkey/ui/CoSignActivity.kt").readText()
        org.junit.Assert.assertFalse("a co-sign QR names its owner by key id", Regex("""else\s+keyId\b""").containsMatchIn(source))
        org.junit.Assert.assertFalse("the co-sign screen reads a public key around the choke point", "getPublicKeyDER(" in source)
        assertEquals(2, Regex("""readOwnPublicKeyDer\([^)]*\)\s*\.orRefuse\(""").findAll(source).count())
    }

    /**
     * #255 verify r4: a QR drawn for one key stayed on screen when the
     * selected key changed, or when a later Generate QR was refused, so the
     * earlier key's QR showed under the newly selected key. The QR is now
     * cleared on every key change and before every generate attempt.
     */
    @Test
    fun aRefusalAfterASuccessLeavesNoQrVisible() {
        val der = byteArrayOf(1, 2, 3)
        io.mockk.mockkObject(com.automatethethings.xkey.qr.QrCodeGenerator)
        every { com.automatethethings.xkey.qr.QrCodeGenerator.generate(any(), any()) } answers {
            android.graphics.Bitmap.createBitmap(1, 1, android.graphics.Bitmap.Config.ARGB_8888)
        }
        var readable = true
        val activity = initiator(listOf(KEY_ID, OTHER_KEY_ID)) { keystore ->
            every { keystore.getPublicKeyDER(KEY_ID, any()) } answers { if (readable) der else null }
            every { keystore.getPublicKeyDER(OTHER_KEY_ID, any()) } throws java.security.KeyStoreException("certificate")
        }
        val generate = CoSignActivity::class.java.getDeclaredMethod("generateInitiatorQR").apply { isAccessible = true }
        val qr = get(activity, "qrImageView") as ImageView
        val spinner = get(activity, "keySpinner") as Spinner

        generate.invoke(activity)
        assertEquals("the readable key's QR is drawn", View.VISIBLE, qr.visibility)

        // A refused regenerate of the same key leaves no earlier QR behind.
        readable = false
        generate.invoke(activity)
        assertNotEquals("a refused QR left the earlier QR visible", View.VISIBLE, qr.visibility)
        assertNull("a refused QR left the earlier QR's image", qr.drawable)

        // A key change clears the QR before any generate.
        readable = true
        generate.invoke(activity)
        assertEquals(View.VISIBLE, qr.visibility)
        spinner.setSelection(1)
        shadowOf(Looper.getMainLooper()).idle()
        assertNotEquals("the earlier key's QR shows under the newly selected key", View.VISIBLE, qr.visibility)

        // And the new key's refusal draws nothing.
        generate.invoke(activity)
        assertNotEquals("a refused QR is visible", View.VISIBLE, qr.visibility)
        assertNull(qr.drawable)
    }

    /** A started screen whose own key load has finished, so it cannot overwrite the keys a test sets. */
    private fun started(): CoSignActivity {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        val loaded = get(activity, "signingKeysLoaded") as kotlinx.coroutines.CompletableDeferred<*>
        MainLooperWait.until("the screen's signing keys never loaded") { loaded.isCompleted }
        shadowOf(Looper.getMainLooper()).idle()
        return activity
    }

    private fun initiator(ids: List<String> = listOf(KEY_ID), stub: (KeystoreManager) -> Unit): CoSignActivity {
        val activity = started()
        val keystore = spyk(KeystoreManager(activity))
        every { keystore.ed25519Prefs() } returns null
        val software = mockk<SoftwareKeyStore>()
        every { software.presence(any()) } returns KeyPresence.ABSENT
        every { keystore.softwareKeys() } returns software
        stub(keystore)
        set(activity, "keystoreManager", keystore)
        set(activity, "currentSignatureData", ContentAuthenticityData(contentHash = "00", signatures = emptyList()))
        set(activity, "signingKeyIds", ids)
        set(activity, "signingKeyTypes", ids.map { "signing" })
        set(activity, "signingKeyMaterials", ids.map { null })
        val spinner = get(activity, "keySpinner") as Spinner
        spinner.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_item, ids)
        spinner.setSelection(0)
        shadowOf(Looper.getMainLooper()).idle()
        return activity
    }

    private fun field(name: String) =
        CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun set(target: Any, name: String, value: Any?) = field(name).set(target, value)

    private fun get(target: Any, name: String): Any? = field(name).get(target)

    private companion object {
        const val KEY_ID = "cosign-key"
        const val OTHER_KEY_ID = "cosign-other-key"
    }
}

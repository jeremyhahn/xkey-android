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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
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
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun generateQrWithAnUnreadableKeyStoreIsARefusalNotACrash() {
        val controller = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()

        val keystore = spyk(KeystoreManager(activity))
        every { keystore.ed25519Prefs() } returns null
        val software = mockk<SoftwareKeyStore>()
        every { software.presence(any()) } returns KeyPresence.UNREADABLE
        every { keystore.softwareKeys() } returns software
        set(activity, "keystoreManager", keystore)
        set(activity, "currentSignatureData", ContentAuthenticityData(contentHash = "00", signatures = emptyList()))
        set(activity, "signingKeyIds", listOf(KEY_ID))
        val spinner = get(activity, "keySpinner") as Spinner
        spinner.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_item, listOf(KEY_ID))
        spinner.setSelection(0)

        val generate = CoSignActivity::class.java.getDeclaredMethod("generateInitiatorQR").apply { isAccessible = true }
        val failure = runCatching { generate.invoke(activity) }.exceptionOrNull()
        assertNull("Generate QR threw on an unreadable key store: ${failure?.cause ?: failure}", failure)

        val qr = get(activity, "qrImageView") as ImageView
        assertNotEquals("no QR is drawn for a key whose store cannot be read", View.VISIBLE, qr.visibility)
    }

    private fun field(name: String) =
        CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun set(target: Any, name: String, value: Any?) = field(name).set(target, value)

    private fun get(target: Any, name: String): Any? = field(name).get(target)

    private companion object {
        const val KEY_ID = "cosign-key"
    }
}

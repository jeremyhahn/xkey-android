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
import android.content.Context
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.BootstrapSettingsData
import com.automatethethings.xkey.settings.BootstrapSettingsRepository
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.testing.MainLooperWait
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * A SPKI pin or Noise static key that is not 64 hex characters is refused by
 * the repository; the settings screen must tell the user and keep the old value.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class SettingsActivityBootstrapRefusalTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val repository by lazy { BootstrapSettingsRepository(context) }

    @Before
    fun setUp() {
        FakeAndroidKeyStore.install()
        runBlocking { repository.clearSettings() }
    }

    @After
    fun tearDown() {
        XKeyDatabase.closeAndClear()
    }

    private fun idleMainLooper() {
        shadowOf(Looper.getMainLooper()).idle()
    }

    /** Idles the main looper until [condition] holds, while the settings load on their own threads. */
    private fun waitUntil(condition: () -> Boolean): Boolean = MainLooperWait.holds(condition)

    private fun isInitializing(activity: SettingsActivity): Boolean =
        SettingsActivity::class.java.getDeclaredField("isInitializing")
            .apply { isAccessible = true }
            .getBoolean(activity)

    private fun views(root: View): Sequence<View> = sequence {
        yield(root)
        if (root is ViewGroup) for (i in 0 until root.childCount) yieldAll(views(root.getChildAt(i)))
    }

    private fun editTextWithLabel(activity: SettingsActivity, label: String): EditText =
        views(activity.window.decorView).filterIsInstance<EditText>()
            .single { it.contentDescription?.toString() == label }

    private fun shownTexts(activity: SettingsActivity): List<String> =
        views(activity.window.decorView).filterIsInstance<TextView>()
            .filter { it.isShown }
            .map { it.text.toString() }
            .toList()

    /** Types [text] in the field labelled [label], fires its focus-lost listener and reports whether [message] is shown. */
    private fun enter(
        scenario: ActivityScenario<SettingsActivity>,
        label: String,
        text: String,
        message: String,
        settled: (BootstrapSettingsData) -> Boolean,
    ): Boolean {
        var shown = false
        scenario.onActivity { activity ->
            assertTrue("settings never finished loading", waitUntil { !isInitializing(activity) })
            val edit = editTextWithLabel(activity, label)
            edit.setText(text)
            edit.onFocusChangeListener.onFocusChange(edit, false)
            waitUntil { message in shownTexts(activity) || settled(runBlocking { repository.getSettings() }) }
            Thread.sleep(200)
            idleMainLooper()
            shown = message in shownTexts(activity)
            assertEquals("the typed text stays in the field", text, editTextWithLabel(activity, label).text.toString())
        }
        return shown
    }

    @Test
    fun `a refused SPKI pin shows a message and stores nothing`() {
        val message = context.getString(R.string.bootstrap_spki_pin_refused)
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            val shown = enter(scenario, context.getString(R.string.bootstrap_spki_pin_label), "xyz", message) { false }
            assertTrue("no refusal message shown", shown)
            assertEquals("", runBlocking { repository.getSettings() }.spkiPinSha256)
        }
    }

    @Test
    fun `a refused Noise static key shows a message and stores nothing`() {
        val message = context.getString(R.string.bootstrap_noise_key_refused)
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            val shown = enter(scenario, context.getString(R.string.bootstrap_noise_static_key), "xyz", message) { false }
            assertTrue("no refusal message shown", shown)
            assertEquals("", runBlocking { repository.getSettings() }.noiseServerStaticKey)
        }
    }

    @Test
    fun `the SPKI refusal says the stored server URL and pin are unchanged`() {
        val message = context.getString(R.string.bootstrap_spki_pin_refused)
        assertTrue(message, message.contains("stored server URL and pin are unchanged"))
    }

    @Test
    fun `the Noise refusal says the stored server address and key are unchanged`() {
        val message = context.getString(R.string.bootstrap_noise_key_refused)
        assertTrue(message, message.contains("stored server address and key are unchanged"))
    }

    private fun <T> field(activity: SettingsActivity, name: String): T =
        @Suppress("UNCHECKED_CAST")
        (SettingsActivity::class.java.getDeclaredField(name).apply { isAccessible = true }.get(activity) as T)

    @Test
    fun `Fetch CA Bundle with an ftp URL shows a message and changes no server`() {
        val message = context.getString(R.string.bootstrap_ca_url_refused)
        val trusted = TrustedComputingSettingsRepository(context)
        val endpointBefore = runBlocking { trusted.getSettings() }.xkmsEndpoint
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue("settings never finished loading", waitUntil { !isInitializing(activity) })
                field<EditText>(activity, "editTextCAUrl").setText("ftp://new.example.com")
                val button = field<Button>(activity, "buttonFetchCA")
                button.performClick()
                assertTrue("no refusal message shown", waitUntil { message in shownTexts(activity) })
                assertTrue("the button is never re-enabled", waitUntil { button.isEnabled })
            }
            assertEquals(endpointBefore, runBlocking { trusted.getSettings() }.xkmsEndpoint)
            assertEquals(BootstrapSettingsData.DEFAULT, runBlocking { repository.getSettings() })
        }
    }

    @Test
    fun `a valid SPKI pin is saved and shows no message`() {
        val pin = "ab".repeat(32)
        val message = context.getString(R.string.bootstrap_spki_pin_refused)
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            val shown = enter(scenario, context.getString(R.string.bootstrap_spki_pin_label), pin, message) {
                it.spkiPinSha256 == pin
            }
            assertFalse("a refusal message was shown for a valid pin", shown)
            assertEquals(pin, runBlocking { repository.getSettings() }.spkiPinSha256)
        }
    }
}

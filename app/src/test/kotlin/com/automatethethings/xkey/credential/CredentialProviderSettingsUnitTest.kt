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
package com.automatethethings.xkey.credential

import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

/**
 * The provider's enable switch, its feature check, the system settings
 * shortcut, and the gate that puts the switch in front of every request.
 *
 * The device test (CredentialProviderSettingsRepositoryTest) covers the
 * stored value on a real device; these cases cover what it does not: the
 * API-level check below API 34, the defaults on a fresh store, the settings
 * shortcut when nothing resolves it, and the gate re-reading the switch.
 *
 * Robolectric runs offline here with only the API 34 framework jar, so the
 * API-level cases run on API 34 and lower `Build.VERSION.SDK_INT` for the
 * check below it, restoring it afterwards.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CredentialProviderSettingsUnitTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var scope: CoroutineScope
    private lateinit var store: DataStore<Preferences>
    private val sdkInt = Build.VERSION.SDK_INT

    @Before
    fun setUp() {
        scope = CoroutineScope(Dispatchers.IO + Job())
        val file = File(folder.root, "credential_provider_settings.preferences_pb")
        store = PreferenceDataStoreFactory.create(scope = scope) { file }
    }

    @After
    fun tearDown() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", sdkInt)
        scope.cancel()
    }

    private fun repository(context: Context = RuntimeEnvironment.getApplication()) =
        CredentialProviderSettingsRepository(context, store)

    // -------------------------------------------------------------------------
    // Feature availability
    // -------------------------------------------------------------------------

    @Test
    fun `the feature is available on API 34`() {
        assertEquals(34, Build.VERSION.SDK_INT)
        assertTrue(repository().isFeatureAvailable())
    }

    @Test
    fun `the feature is not available below API 34`() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 33)

        assertFalse(repository().isFeatureAvailable())
    }

    @Test
    fun `the feature stays available above API 34`() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 35)

        assertTrue(repository().isFeatureAvailable())
    }

    // -------------------------------------------------------------------------
    // Stored switch
    // -------------------------------------------------------------------------

    @Test
    fun `the switch is off before anything is written`() = runBlocking {
        val repository = repository()

        assertFalse(repository.isEnabled())
        assertFalse(repository.getSettings().isEnabled)
        assertFalse(repository.settingsFlow.first().isEnabled)
    }

    @Test
    fun `the app's own store is off before anything is written`() = runBlocking {
        val repository = CredentialProviderSettingsRepository(RuntimeEnvironment.getApplication())

        assertFalse(repository.isEnabled())
    }

    @Test
    fun `setEnabled round trips on and back off`() = runBlocking {
        val repository = repository()

        repository.setEnabled(true)
        assertTrue(repository.isEnabled())
        assertTrue(repository.getSettings().isEnabled)

        repository.setEnabled(false)
        assertFalse(repository.isEnabled())
        assertFalse(repository.getSettings().isEnabled)
    }

    @Test
    fun `the settings flow emits the new value after a write`() = runBlocking {
        val repository = repository()
        assertFalse(repository.settingsFlow.first().isEnabled)

        repository.setEnabled(true)

        assertTrue(withTimeout(5_000) { repository.settingsFlow.first { it.isEnabled } }.isEnabled)
    }

    @Test
    fun `a second repository on the same store reads the written value`() = runBlocking {
        repository().setEnabled(true)

        assertTrue(repository().isEnabled())
    }

    @Test
    fun `clearSettings returns the switch to off`() = runBlocking {
        val repository = repository()
        repository.setEnabled(true)

        repository.clearSettings()

        assertFalse(repository.isEnabled())
        assertFalse(repository().isEnabled())
    }

    @Test
    fun `clearSettings on a fresh store leaves the switch off`() = runBlocking {
        val repository = repository()

        repository.clearSettings()

        assertFalse(repository.isEnabled())
    }

    // -------------------------------------------------------------------------
    // System settings shortcut
    // -------------------------------------------------------------------------

    @Test
    fun `opening system settings starts the credential provider page as a new task`() {
        val application = RuntimeEnvironment.getApplication()

        assertTrue(repository(application).openSystemCredentialSettings())

        val started = shadowOf(application).nextStartedActivity
        assertEquals("android.settings.CREDENTIAL_PROVIDER", started.action)
        assertTrue(started.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
    }

    @Test
    fun `opening system settings falls back to security settings`() {
        val context = mockk<Context>()
        val started = slot<Intent>()
        every {
            context.startActivity(match { it.action == "android.settings.CREDENTIAL_PROVIDER" })
        } throws ActivityNotFoundException()
        every { context.startActivity(match { it.action == Settings.ACTION_SECURITY_SETTINGS }) } answers {
            started.captured = firstArg()
        }

        assertTrue(repository(context).openSystemCredentialSettings())

        assertEquals(Settings.ACTION_SECURITY_SETTINGS, started.captured.action)
        assertTrue(started.captured.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
    }

    @Test
    fun `opening system settings returns false when no activity resolves either page`() {
        val application = RuntimeEnvironment.getApplication()
        shadowOf(application).checkActivities(true)

        assertFalse(repository(application).openSystemCredentialSettings())
    }

    @Test
    fun `opening system settings returns false when starting either page throws`() {
        val context = mockk<Context>()
        every { context.startActivity(any()) } throws ActivityNotFoundException()

        assertFalse(repository(context).openSystemCredentialSettings())

        verify(exactly = 2) { context.startActivity(any()) }
    }

    // -------------------------------------------------------------------------
    // Enable gate
    // -------------------------------------------------------------------------

    @Test
    fun `the gate reads the switch once for every request`() = runBlocking {
        var reads = 0
        val gate = CredentialProviderEnableGate { reads++; true }
        val created = BeginCreateCredentialResponse()
        val found = BeginGetCredentialResponse()

        repeat(3) {
            assertSame(created, gate.beginCreate(mockk<BeginCreateCredentialRequest>()) { created })
            assertSame(found, gate.beginGet(mockk<BeginGetCredentialRequest>()) { found })
        }

        assertEquals(6, reads)
    }

    @Test
    fun `the gate follows the stored switch between requests`() = runBlocking {
        val repository = repository()
        val gate = CredentialProviderEnableGate(repository::isEnabled)
        var handled = 0
        val created = BeginCreateCredentialResponse()
        val found = BeginGetCredentialResponse()

        gate.beginCreate(mockk()) { handled++; created }
        gate.beginGet(mockk()) { handled++; found }
        assertEquals("off: no handler runs", 0, handled)

        repository.setEnabled(true)
        assertSame(created, gate.beginCreate(mockk()) { handled++; created })
        assertSame(found, gate.beginGet(mockk()) { handled++; found })
        assertEquals("on: each request reaches its handler", 2, handled)

        repository.setEnabled(false)
        val off = gate.beginCreate(mockk()) { handled++; created }
        assertTrue(off.createEntries.isEmpty())
        assertTrue(gate.beginGet(mockk()) { handled++; found }.credentialEntries.isEmpty())
        assertEquals("off again: no handler runs", 2, handled)
    }
}

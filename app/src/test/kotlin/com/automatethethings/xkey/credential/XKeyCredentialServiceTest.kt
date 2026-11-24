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
import android.content.pm.SigningInfo
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The service is the provider's front door: the system credential manager
 * calls its three request callbacks, and each must answer exactly once.
 *
 * The handlers are replaced through their constructors, so what is under
 * test is the service itself: the enable switch in front of the handlers,
 * the error mapping and the clear-state answer. The switch is read from a
 * [CredentialProviderSettingsRepository] replaced the same way. The
 * handlers' own collaborators (Android Keystore, the Room database) are
 * stubbed so that constructing a handler touches no device storage.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class XKeyCredentialServiceTest {

    private val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
    private val keyDao = mockk<KeyDao>(relaxed = true)

    private val createEntry = mockk<CreateEntry>()
    private val passkeyEntry = mockk<PublicKeyCredentialEntry>()

    private lateinit var service: XKeyCredentialService

    @Before
    fun setUp() {
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.credentialMetadataDao() } returns credentialDao
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkConstructor(CredentialProviderSettingsRepository::class)
        mockkConstructor(CreateCredentialHandler::class)
        mockkConstructor(GetCredentialHandler::class)
        coEvery { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) } returns
            BeginCreateCredentialResponse(createEntries = listOf(createEntry))
        coEvery { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(any()) } returns
            BeginGetCredentialResponse(credentialEntries = listOf(passkeyEntry))

        service = Robolectric.buildService(XKeyCredentialService::class.java).create().get()
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun setSwitch(enabled: Boolean) {
        coEvery { anyConstructed<CredentialProviderSettingsRepository>().isEnabled() } returns enabled
    }

    // -------------------------------------------------------------------------
    // The enable switch
    // -------------------------------------------------------------------------

    @Test
    fun `switched off, begin-create answers no entries and never calls the handler`() {
        setSwitch(false)
        val callback = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()

        service.onBeginCreateCredentialRequest(mockk<BeginCreateCredentialRequest>(), CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.errors.size)
        assertEquals(1, callback.results.size)
        assertTrue(callback.results.single().createEntries.isEmpty())
        coVerify(exactly = 0) { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) }
    }

    @Test
    fun `switched off, begin-get answers no entries and never calls the handler`() {
        setSwitch(false)
        val callback = Recorder<BeginGetCredentialResponse, GetCredentialException>()

        service.onBeginGetCredentialRequest(mockk<BeginGetCredentialRequest>(), CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.errors.size)
        assertEquals(1, callback.results.size)
        assertTrue(callback.results.single().credentialEntries.isEmpty())
        coVerify(exactly = 0) { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(any()) }
    }

    @Test
    fun `switched on, begin-create answers the handler's entries`() {
        setSwitch(true)
        val request = mockk<BeginCreateCredentialRequest>()
        val callback = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()

        service.onBeginCreateCredentialRequest(request, CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.errors.size)
        assertEquals(listOf(createEntry), callback.results.single().createEntries)
        coVerify(exactly = 1) { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(request) }
    }

    @Test
    fun `switched on, begin-get answers the handler's entries`() {
        setSwitch(true)
        val request = mockk<BeginGetCredentialRequest>()
        val callback = Recorder<BeginGetCredentialResponse, GetCredentialException>()

        service.onBeginGetCredentialRequest(request, CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.errors.size)
        assertEquals(listOf(passkeyEntry), callback.results.single().credentialEntries)
        coVerify(exactly = 1) { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(request) }
    }

    @Test
    fun `the switch is read again for each request`() {
        setSwitch(true)
        val first = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()
        service.onBeginCreateCredentialRequest(mockk(), CancellationSignal(), first)
        first.await()

        setSwitch(false)
        val second = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()
        service.onBeginCreateCredentialRequest(mockk(), CancellationSignal(), second)
        second.await()

        assertEquals(1, first.results.single().createEntries.size)
        assertTrue(second.results.single().createEntries.isEmpty())
        coVerify(exactly = 1) { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) }
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    @Test
    fun `a create handler that throws reaches onError with the unknown create exception`() {
        setSwitch(true)
        coEvery { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) } throws
            IllegalStateException("store unavailable")
        val callback = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()

        service.onBeginCreateCredentialRequest(mockk(), CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.results.size)
        val error = callback.errors.single()
        assertTrue("got $error", error is CreateCredentialUnknownException)
        assertEquals("store unavailable", error.errorMessage)
    }

    @Test
    fun `a get handler that throws reaches onError with the unknown get exception`() {
        setSwitch(true)
        coEvery { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(any()) } throws
            IllegalStateException("store unavailable")
        val callback = Recorder<BeginGetCredentialResponse, GetCredentialException>()

        service.onBeginGetCredentialRequest(mockk(), CancellationSignal(), callback)

        callback.await()
        assertEquals(0, callback.results.size)
        val error = callback.errors.single()
        assertTrue("got $error", error is GetCredentialUnknownException)
        assertEquals("store unavailable", error.errorMessage)
    }

    @Test
    fun `a failing switch read reaches onError rather than leaving the caller waiting`() {
        coEvery { anyConstructed<CredentialProviderSettingsRepository>().isEnabled() } throws
            java.io.IOException("settings unreadable")
        val create = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()
        val get = Recorder<BeginGetCredentialResponse, GetCredentialException>()

        service.onBeginCreateCredentialRequest(mockk(), CancellationSignal(), create)
        service.onBeginGetCredentialRequest(mockk(), CancellationSignal(), get)

        create.await()
        get.await()
        assertTrue(create.results.isEmpty() && get.results.isEmpty())
        assertTrue(create.errors.single() is CreateCredentialUnknownException)
        assertTrue(get.errors.single() is GetCredentialUnknownException)
    }

    /**
     * A handler cancelled from inside (a timeout, say) throws a
     * [CancellationException]. The caller must still get exactly one answer:
     * an error, never silence and never two callbacks.
     */
    @Test
    fun `a handler's cancellation still answers exactly once with an error`() {
        setSwitch(true)
        coEvery { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) } throws
            CancellationException("timed out")
        coEvery { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(any()) } throws
            CancellationException("timed out")
        val create = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()
        val get = Recorder<BeginGetCredentialResponse, GetCredentialException>()

        service.onBeginCreateCredentialRequest(mockk(), CancellationSignal(), create)
        service.onBeginGetCredentialRequest(mockk(), CancellationSignal(), get)

        create.await()
        get.await()
        assertEquals(1, create.calls)
        assertEquals(1, get.calls)
        assertTrue(create.errors.single() is CreateCredentialUnknownException)
        assertTrue(get.errors.single() is GetCredentialUnknownException)
    }

    /**
     * The service ignores the cancellation signal: a request the caller
     * cancelled before the answer still gets its one answer, which the
     * framework drops. It is never answered twice.
     */
    @Test
    fun `a request cancelled by the caller is still answered exactly once`() {
        setSwitch(true)
        val signal = CancellationSignal().apply { cancel() }
        val callback = Recorder<BeginCreateCredentialResponse, CreateCredentialException>()

        service.onBeginCreateCredentialRequest(mockk(), signal, callback)

        callback.await()
        assertEquals(1, callback.calls)
        assertEquals(1, callback.results.size)
    }

    // -------------------------------------------------------------------------
    // Clear state
    // -------------------------------------------------------------------------

    @Test
    fun `clear credential state answers null and deletes nothing`() {
        setSwitch(true)
        val callback = Recorder<Void?, ClearCredentialException>()

        service.onClearCredentialStateRequest(
            ProviderClearCredentialStateRequest(CallingAppInfo("com.example.caller", SigningInfo())),
            CancellationSignal(),
            callback,
        )

        callback.await()
        assertEquals(1, callback.calls)
        assertNull(callback.results.single())
        verify { credentialDao wasNot io.mockk.Called }
        verify { keyDao wasNot io.mockk.Called }
        coVerify(exactly = 0) { anyConstructed<CreateCredentialHandler>().handleBeginCreateCredential(any()) }
        coVerify(exactly = 0) { anyConstructed<GetCredentialHandler>().handleBeginGetCredential(any()) }
    }

    /**
     * Records every callback. [await] waits for the first, then a moment
     * longer, so a second callback (which would break the receiver's
     * contract) is counted too.
     */
    private class Recorder<R, E : Throwable> : OutcomeReceiver<R, E> {
        val results = java.util.Collections.synchronizedList(mutableListOf<R>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<E>())
        private val first = CountDownLatch(1)

        val calls: Int get() = results.size + errors.size

        override fun onResult(result: R) {
            results += result
            first.countDown()
        }

        override fun onError(error: E) {
            errors += error
            first.countDown()
        }

        fun await() {
            assertTrue("the callback never fired", first.await(5, TimeUnit.SECONDS))
            Thread.sleep(SETTLE_MILLIS)
        }
    }

    private companion object {
        const val SETTLE_MILLIS = 200L
    }
}

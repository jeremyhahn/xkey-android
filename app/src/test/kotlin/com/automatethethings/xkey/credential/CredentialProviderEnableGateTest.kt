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

import android.content.Context
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import io.mockk.mockk
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests that the passkey provider honours the user's enable switch.
 *
 * The handlers stand in as lambdas that answer what they would answer today:
 * one create entry, and one credential entry for a passkey stored for the
 * request's relying party. The setting is read through a
 * [CredentialProviderSettingsRepository] over an in-memory store, so no
 * Android storage is touched.
 */
class CredentialProviderEnableGateTest {

    private val createEntry = mockk<CreateEntry>()
    private val storedPasskeyEntry = mockk<PublicKeyCredentialEntry>()

    private var createHandlerCalls = 0
    private var getHandlerCalls = 0

    private val createHandler: suspend (BeginCreateCredentialRequest) -> BeginCreateCredentialResponse = {
        createHandlerCalls++
        BeginCreateCredentialResponse(createEntries = listOf(createEntry))
    }

    private val getHandler: suspend (BeginGetCredentialRequest) -> BeginGetCredentialResponse = {
        getHandlerCalls++
        BeginGetCredentialResponse(credentialEntries = listOf(storedPasskeyEntry))
    }

    private val createRequest = mockk<BeginCreateCredentialRequest>()
    private val getRequest = mockk<BeginGetCredentialRequest>()

    private fun repository(): CredentialProviderSettingsRepository =
        CredentialProviderSettingsRepository(mockk<Context>(relaxed = true), InMemoryPreferences())

    private fun gate(repository: CredentialProviderSettingsRepository) =
        CredentialProviderEnableGate(repository::isEnabled)

    @Test
    fun settingOff_beginCreateOffersNoCreateEntries() = runTest {
        val repository = repository().apply { setEnabled(false) }

        val response = gate(repository).beginCreate(createRequest, createHandler)

        assertTrue(response.createEntries.isEmpty())
        assertEquals(0, createHandlerCalls)
    }

    @Test
    fun settingOff_beginGetOffersNoCredentialEntriesEvenWithAStoredPasskey() = runTest {
        val repository = repository().apply { setEnabled(false) }

        val response = gate(repository).beginGet(getRequest, getHandler)

        assertTrue(response.credentialEntries.isEmpty())
        assertEquals(0, getHandlerCalls)
    }

    @Test
    fun settingOn_beginCreateAndBeginGetReturnTheHandlersEntries() = runTest {
        val repository = repository().apply { setEnabled(true) }
        val gate = gate(repository)

        val created = gate.beginCreate(createRequest, createHandler)
        val got = gate.beginGet(getRequest, getHandler)

        assertEquals(listOf(createEntry), created.createEntries)
        assertEquals(listOf(storedPasskeyEntry), got.credentialEntries)
        assertEquals(1, createHandlerCalls)
        assertEquals(1, getHandlerCalls)
    }

    @Test
    fun nothingStored_providerIsOffByDefault() = runTest {
        val repository = repository()
        assertFalse(repository.isEnabled())

        val gate = gate(repository)
        val created = gate.beginCreate(createRequest, createHandler)
        val got = gate.beginGet(getRequest, getHandler)

        assertTrue(created.createEntries.isEmpty())
        assertTrue(got.credentialEntries.isEmpty())
        assertEquals(0, createHandlerCalls + getHandlerCalls)
    }

    @Test
    fun theSwitchIsReadOnEveryCall() = runTest {
        val repository = repository().apply { setEnabled(true) }
        val gate = gate(repository)
        assertEquals(1, gate.beginCreate(createRequest, createHandler).createEntries.size)

        repository.setEnabled(false)

        assertTrue(gate.beginCreate(createRequest, createHandler).createEntries.isEmpty())
        assertTrue(gate.beginGet(getRequest, getHandler).credentialEntries.isEmpty())
    }

    /** A [DataStore] held in memory, standing in for the app's preferences file. */
    private class InMemoryPreferences : DataStore<Preferences> {
        private val state = MutableStateFlow(emptyPreferences())

        override val data: Flow<Preferences> = state

        override suspend fun updateData(transform: suspend (t: Preferences) -> Preferences): Preferences {
            val updated = transform(state.value)
            state.value = updated
            return updated
        }
    }
}

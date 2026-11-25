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
package com.automatethethings.xkey.credential.handler

import android.app.Application
import android.app.PendingIntent
import android.content.Intent
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.credential.ui.CredentialSelectorActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * The pending intents the provider hands the system credential picker.
 *
 * The picker fires the one the user chooses, and the framework fills the
 * provider request into it before it starts [CredentialSelectorActivity]:
 * so each intent must be an activity intent for the selector, carry the
 * action and extras the selector reads, be mutable, and stay distinct from
 * every other entry's intent, or a later entry would overwrite the extras
 * of an earlier one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CredentialPendingIntentHelperTest {

    private val context get() = RuntimeEnvironment.getApplication()

    private fun saved(pendingIntent: PendingIntent): Intent = shadowOf(pendingIntent).savedIntent

    // -------------------------------------------------------------------------
    // Create
    // -------------------------------------------------------------------------

    @Test
    fun `a create intent starts the selector with the create action and the request`() {
        val pendingIntent = CredentialPendingIntentHelper.createCreatePendingIntent(context, CREATE_JSON)

        assertTrue(shadowOf(pendingIntent).isActivityIntent)
        val intent = saved(pendingIntent)
        assertEquals(CredentialSelectorActivity::class.java.name, intent.component?.className)
        assertEquals(context.packageName, intent.component?.packageName)
        assertEquals(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL, intent.action)
        assertEquals(CREATE_JSON, intent.getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
        assertNull(
            "a create intent names no credential",
            intent.getStringExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID),
        )
        assertNotNull(
            "the selector's prompt takes a turn in the prompt queue",
            intent.getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY),
        )
    }

    @Test
    fun `a create intent is mutable so the framework can fill in the request`() {
        val flags = shadowOf(CredentialPendingIntentHelper.createCreatePendingIntent(context, CREATE_JSON)).flags

        assertTrue("FLAG_MUTABLE", flags and PendingIntent.FLAG_MUTABLE != 0)
        assertFalse("not FLAG_IMMUTABLE", flags and PendingIntent.FLAG_IMMUTABLE != 0)
    }

    // -------------------------------------------------------------------------
    // Get
    // -------------------------------------------------------------------------

    @Test
    fun `a get intent starts the selector with the get action, the credential and the request`() {
        val pendingIntent = CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_A, GET_JSON)

        assertTrue(shadowOf(pendingIntent).isActivityIntent)
        val intent = saved(pendingIntent)
        assertEquals(CredentialSelectorActivity::class.java.name, intent.component?.className)
        assertEquals(CredentialSelectorActivity.ACTION_GET_CREDENTIAL, intent.action)
        assertEquals(CREDENTIAL_A, intent.getStringExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID))
        assertEquals(GET_JSON, intent.getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
        assertNotNull(intent.getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY))
    }

    @Test
    fun `a get intent is mutable so the framework can fill in the request`() {
        val flags = shadowOf(
            CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_A, GET_JSON)
        ).flags

        assertTrue("FLAG_MUTABLE", flags and PendingIntent.FLAG_MUTABLE != 0)
        assertFalse("not FLAG_IMMUTABLE", flags and PendingIntent.FLAG_IMMUTABLE != 0)
    }

    // -------------------------------------------------------------------------
    // No collisions
    // -------------------------------------------------------------------------

    /**
     * The picker lists one entry per stored passkey. Pending intents that
     * differ only in their extras are the same pending intent to the system,
     * and FLAG_UPDATE_CURRENT would hand every entry the last one's
     * credential id; distinct request codes keep them apart.
     */
    @Test
    fun `two get entries keep their own credential ids`() {
        val first = CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_A, GET_JSON)
        val second = CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_B, GET_JSON)

        assertNotEquals(shadowOf(first).requestCode, shadowOf(second).requestCode)
        assertEquals(CREDENTIAL_A, saved(first).getStringExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID))
        assertEquals(CREDENTIAL_B, saved(second).getStringExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID))
    }

    @Test
    fun `create and get intents do not share a request code`() {
        val create = CredentialPendingIntentHelper.createCreatePendingIntent(context, CREATE_JSON)
        val get = CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_A, GET_JSON)

        assertNotEquals(shadowOf(create).requestCode, shadowOf(get).requestCode)
        assertEquals(CREATE_JSON, saved(create).getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
        assertEquals(GET_JSON, saved(get).getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
    }

    @Test
    fun `two create intents for different requests keep their own request`() {
        val otherJson = """{"rp":{"id":"other.example.com"},"challenge":"b3RoZXI"}"""
        val first = CredentialPendingIntentHelper.createCreatePendingIntent(context, CREATE_JSON)
        val second = CredentialPendingIntentHelper.createCreatePendingIntent(context, otherJson)

        assertNotEquals(shadowOf(first).requestCode, shadowOf(second).requestCode)
        assertEquals(CREATE_JSON, saved(first).getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
        assertEquals(otherJson, saved(second).getStringExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON))
    }

    @Test
    fun `each intent takes its own prompt key`() {
        val keys = listOf(
            CredentialPendingIntentHelper.createCreatePendingIntent(context, CREATE_JSON),
            CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_A, GET_JSON),
            CredentialPendingIntentHelper.createGetPendingIntent(context, CREDENTIAL_B, GET_JSON),
        ).map { saved(it).getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY) }

        assertEquals(keys.size, keys.toSet().size)
    }

    private companion object {
        const val CREATE_JSON = """{"rp":{"id":"example.com","name":"Example"},"challenge":"Y2hhbGxlbmdl"}"""
        const val GET_JSON = """{"rpId":"example.com","challenge":"Y2hhbGxlbmdl"}"""
        const val CREDENTIAL_A = "Y3JlZGVudGlhbC1h"
        const val CREDENTIAL_B = "Y3JlZGVudGlhbC1i"
    }
}

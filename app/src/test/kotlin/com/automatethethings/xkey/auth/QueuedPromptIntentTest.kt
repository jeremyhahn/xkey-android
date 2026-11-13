/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.auth

import android.app.Application
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * An activity the system starts from a pending intent (the Credential
 * Manager's) takes its queue entry under the key [PromptOwnership.queued]
 * gave the intent, once.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class QueuedPromptIntentTest {

    @Test
    fun `a queued intent's activity enqueues under the intent's key`() {
        val intent = PromptOwnership.queued(Intent(), "credentialSelector")
        val key = intent.getStringExtra(PromptOwnership.EXTRA_PROMPT_KEY)
        assertNotNull("the intent carries a queue key", key)
        assertEquals(key, PromptOwnership.promptKey(intent, "credentialSelector"))
    }

    @Test
    fun `a relaunch of a queued intent takes a fresh key, never the one already enqueued`() {
        val intent = PromptOwnership.queued(Intent(), "credentialSelector")
        val first = PromptOwnership.promptKey(intent, "credentialSelector")
        PromptOwnership.process.enqueue(first) {}
        try {
            assertNotEquals(first, PromptOwnership.promptKey(intent, "credentialSelector"))
        } finally {
            PromptOwnership.process.end(first)
        }
        assertNotEquals(first, PromptOwnership.promptKey(intent, "credentialSelector"))
    }

    @Test
    fun `an intent without a key gets a fresh one`() {
        val a = PromptOwnership.promptKey(Intent(), "credentialSelector")
        val b = PromptOwnership.promptKey(null, "credentialSelector")
        assertNotEquals(a, b)
    }
}

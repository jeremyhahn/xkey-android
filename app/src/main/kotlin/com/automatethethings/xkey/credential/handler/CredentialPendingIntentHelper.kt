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
package com.automatethethings.xkey.credential.handler

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.credential.ui.CredentialSelectorActivity
import java.util.concurrent.atomic.AtomicInteger

/**
 * Helper class for creating PendingIntents for credential operations.
 *
 * Creates unique PendingIntents for the CredentialManager system to use
 * when launching credential selection and creation activities.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
object CredentialPendingIntentHelper {

    private val requestCodeCounter = AtomicInteger(0)

    /**
     * Create a PendingIntent for credential creation.
     *
     * @param context The context.
     * @param requestJson The WebAuthn create request JSON.
     * @return PendingIntent for launching the creation flow.
     */
    fun createCreatePendingIntent(
        context: Context,
        requestJson: String
    ): PendingIntent {
        val intent = PromptOwnership.queued(
            Intent(context, CredentialSelectorActivity::class.java).apply {
                action = CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL
                putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, requestJson)
            },
            "credentialSelector",
        )

        return PendingIntent.getActivity(
            context,
            requestCodeCounter.incrementAndGet(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    /**
     * Create a PendingIntent for credential assertion.
     *
     * @param context The context.
     * @param credentialId The selected credential ID.
     * @param requestJson The WebAuthn get request JSON.
     * @return PendingIntent for launching the assertion flow.
     */
    fun createGetPendingIntent(
        context: Context,
        credentialId: String,
        requestJson: String
    ): PendingIntent {
        val intent = PromptOwnership.queued(
            Intent(context, CredentialSelectorActivity::class.java).apply {
                action = CredentialSelectorActivity.ACTION_GET_CREDENTIAL
                putExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID, credentialId)
                putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, requestJson)
            },
            "credentialSelector",
        )

        return PendingIntent.getActivity(
            context,
            requestCodeCounter.incrementAndGet(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }
}

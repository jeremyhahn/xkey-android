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
package com.automatethethings.xkey.protocol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * The owner's answer to one co-sign prompt.
 */
sealed class CosignPromptOutcome {
    data object Approved : CosignPromptOutcome()
    data class Refused(val message: String) : CosignPromptOutcome()
}

/**
 * The co-sign was not approved: refused, cancelled or timed out.
 */
class CosignNotApprovedException(message: String) : Exception(message)

/**
 * Where a co-sign prompt is shown. [show] puts up the prompt for [requestId]
 * and calls [onResult] when the owner answers it; [dismiss] takes down what
 * [show] put up once the request settles, times out or is cancelled.
 */
interface CosignPromptSurface {
    fun show(
        requestId: String,
        title: String,
        subtitle: String,
        locked: Boolean,
        onResult: (requestId: String, outcome: CosignPromptOutcome) -> Unit
    )

    fun dismiss(requestId: String)
}

/**
 * Asks the owner to approve co-signatures one at a time (#177).
 *
 * The approval activity is single-top and reads its request only when it is
 * created, so a second prompt launched over a visible one is dropped. Prompts
 * are therefore serialized: a second co-sign waits until the first settles or
 * times out. Each prompt has its own request id, and only an answer carrying
 * that id settles it.
 *
 * @param surface Shows and dismisses the prompts.
 * @param timeoutMs How long one prompt waits for the owner before it fails.
 */
class CosignApprovalPrompts(
    private val surface: CosignPromptSurface,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS
) {
    private val promptLock = Mutex()
    private val requestIds = AtomicLong(0L)
    private val pending = ConcurrentHashMap<String, CompletableDeferred<CosignPromptOutcome>>()

    /**
     * Returns when the owner approves; throws [CosignNotApprovedException]
     * on a refusal or at the timeout. Cancelling the caller dismisses the
     * prompt and releases the next one.
     */
    suspend fun approve(title: String, subtitle: String, locked: Boolean) {
        promptLock.withLock {
            val requestId = "$REQUEST_ID_PREFIX${requestIds.incrementAndGet()}"
            val answer = CompletableDeferred<CosignPromptOutcome>()
            pending[requestId] = answer
            try {
                surface.show(requestId, title, subtitle, locked, ::complete)
                val outcome = withTimeoutOrNull(timeoutMs) { answer.await() }
                    ?: throw CosignNotApprovedException("no answer within ${timeoutMs / 1000} s")
                if (outcome is CosignPromptOutcome.Refused) {
                    throw CosignNotApprovedException(outcome.message)
                }
            } finally {
                pending.remove(requestId)
                surface.dismiss(requestId)
            }
        }
    }

    /**
     * Settles the prompt [requestId]. An unknown or already settled id is
     * ignored: a late answer to a timed-out prompt approves nothing.
     */
    fun complete(requestId: String, outcome: CosignPromptOutcome): Boolean =
        pending.remove(requestId)?.complete(outcome) ?: false

    companion object {
        /** One prompt's wait for the owner, as long as its lock-screen notification. */
        const val DEFAULT_TIMEOUT_MS = 60_000L

        /** Co-sign request ids; the biometric launcher ignores non-numeric ids. */
        const val REQUEST_ID_PREFIX = "cosign-"
    }
}

/**
 * Shows a co-sign prompt as [TransparentBiometricActivity]. On a locked phone
 * the lock-screen notification carries the same intent, so whichever starts
 * the activity, its answer has the prompt's own request id.
 */
class ActivityCosignPromptSurface(
    private val context: Context,
    private val notificationHelper: BiometricNotificationHelper,
    private val notificationTimeoutMs: Long = CosignApprovalPrompts.DEFAULT_TIMEOUT_MS
) : CosignPromptSurface {

    private val receivers = ConcurrentHashMap<String, BroadcastReceiver>()

    override fun show(
        requestId: String,
        title: String,
        subtitle: String,
        locked: Boolean,
        onResult: (requestId: String, outcome: CosignPromptOutcome) -> Unit
    ) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val outcome = outcomeOf(requestId, intent) ?: return
                onResult(requestId, outcome)
            }
        }
        receivers[requestId] = receiver
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        val intent = TransparentBiometricActivity.createIntent(
            context = context,
            requestId = requestId,
            title = title,
            subtitle = subtitle,
            description = null,
            showOnLockScreen = locked
        ).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (locked) {
            notificationHelper.showBiometricRequiredNotification(
                operationType = "sign",
                rpName = null,
                requestId = requestId,
                timeoutMs = notificationTimeoutMs,
                promptIntent = intent
            )
        }
        context.startActivity(intent)
    }

    override fun dismiss(requestId: String) {
        receivers.remove(requestId)?.let { receiver ->
            try {
                context.unregisterReceiver(receiver)
            } catch (e: IllegalArgumentException) {
                // Already unregistered
            }
        }
        notificationHelper.cancelNotification()
    }

    companion object {
        /**
         * The outcome a result broadcast carries for [requestId], or null when
         * it answers another prompt.
         */
        fun outcomeOf(requestId: String, intent: Intent): CosignPromptOutcome? {
            if (intent.action != TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT) return null
            if (intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID) != requestId) {
                return null
            }
            if (intent.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, false)) {
                return CosignPromptOutcome.Approved
            }
            val message = intent.getStringExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE)
            return CosignPromptOutcome.Refused(message ?: "Prompt cancelled")
        }
    }
}

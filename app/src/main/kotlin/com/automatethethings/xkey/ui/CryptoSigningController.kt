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

package com.automatethethings.xkey.ui

import androidx.biometric.BiometricPrompt
import java.util.Base64
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The signing prompts on screen, by request id, so the service that launched
 * one can take it down when the request it answers is cancelled -- the session
 * revoked or unpaired, the transport gone, the handler timed out (Codex 7346).
 *
 * A cancel names one request and reaches only that request's prompt. One that
 * lands before its activity has come up is remembered, so the activity, when
 * it does, finishes without prompting. Request ids are never reused within a
 * process, so the record only has to outlive the launch.
 */
object CryptoSigningCancellations {
    private const val MAX_REMEMBERED = 64

    private val live = HashMap<String, CryptoSigningController>()
    private val cancelled = LinkedHashSet<String>()

    /** False when [controller]'s request was already cancelled. */
    @Synchronized
    fun register(controller: CryptoSigningController): Boolean {
        if (controller.requestId in cancelled) return false
        live[controller.requestId] = controller
        return true
    }

    /** Removes [controller], and only it: a recreated activity has replaced it. */
    @Synchronized
    fun unregister(controller: CryptoSigningController) {
        if (live[controller.requestId] === controller) live.remove(controller.requestId)
    }

    /** Takes down [requestId]'s prompt, now or when its activity comes up. */
    fun cancel(requestId: String) {
        val controller = synchronized(this) {
            cancelled.add(requestId)
            while (cancelled.size > MAX_REMEMBERED) cancelled.remove(cancelled.first())
            live.remove(requestId)
        }
        controller?.cancel()
    }
}

/**
 * The decisions [CryptoSigningActivity] makes for one signing request, apart
 * from the Android types, so they can be tested on the JVM.
 *
 * Once the request is cancelled nothing is signed and nothing is delivered:
 * the prompt is cancelled, the activity finishes, and an authentication that
 * succeeds anyway -- the user's touch racing the revocation -- is dropped
 * before the key is used. Otherwise exactly one result is delivered.
 *
 * Everything but [cancel] runs on the main thread; [cancel] may be called from
 * any thread and does its work on [mainExecutor].
 */
class CryptoSigningController(
    val requestId: String,
    private val mainExecutor: Executor,
    private val deliverSuccess: (signatureBase64: String) -> Unit,
    private val deliverError: (code: Int, message: String) -> Unit,
    private val finish: () -> Unit,
) {
    /** The biometric prompt this request is showing. */
    fun interface Prompt {
        fun cancelAuthentication()
    }

    private val cancelled = AtomicBoolean(false)
    @Volatile private var prompt: Prompt? = null
    private var settled = false

    val isCancelled: Boolean get() = cancelled.get()

    /**
     * Registers the request so a cancel can reach it.
     *
     * @return false when it was cancelled before the activity came up; the
     *   activity has then been finished and must not prompt
     */
    fun start(): Boolean {
        if (CryptoSigningCancellations.register(this)) return true
        cancelled.set(true)
        settled = true
        finish()
        return false
    }

    /**
     * Records the prompt about to be shown, so a cancel can dismiss it.
     *
     * @return false when the request is already cancelled: do not show it
     */
    fun attach(prompt: Prompt): Boolean {
        this.prompt = prompt
        return !cancelled.get()
    }

    /** Dismisses the prompt and finishes, delivering nothing. */
    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        mainExecutor.execute {
            settled = true
            prompt?.cancelAuthentication()
            finish()
        }
    }

    /**
     * The user authenticated: [sign] with the unlocked key and deliver the
     * signature -- unless the request was cancelled, in which case the key is
     * not used, or is cancelled while signing, in which case the signature is
     * dropped.
     */
    fun succeed(sign: () -> ByteArray) {
        if (cancelled.get() || settled) return
        settled = true
        val signature = try {
            sign()
        } catch (e: Exception) {
            if (!cancelled.get()) deliverError(ERROR_CODE_SIGNING_FAILED, "Signing failed: ${e.message}")
            finish()
            return
        }
        if (!cancelled.get()) deliverSuccess(Base64.getEncoder().encodeToString(signature))
        finish()
    }

    /** The request failed; nothing is delivered once it was cancelled or settled. */
    fun fail(code: Int, message: String) {
        if (cancelled.get() || settled) return
        settled = true
        deliverError(code, message)
        finish()
    }

    /**
     * The activity is going away: stop listening and dismiss the prompt.
     *
     * Nothing this controller's prompt reports afterwards is delivered. An
     * unsettled request is refused as cancelled by the user when the activity
     * is gone for good -- swiped away, navigated off, finished by the system
     * -- so whoever waits on it is answered and the next prompt can come up.
     * When the activity is only [recreating] for a configuration change, the
     * new instance takes the request over and answers it.
     */
    fun release(recreating: Boolean) {
        CryptoSigningCancellations.unregister(this)
        val unsettled = !settled && !cancelled.get()
        settled = true
        prompt?.cancelAuthentication()
        if (unsettled && !recreating) deliverError(ERROR_CODE_CLOSED, "The signing prompt was closed")
    }

    private companion object {
        const val ERROR_CODE_SIGNING_FAILED = CryptoSigningActivity.ERROR_CODE_SIGNING_FAILED
        const val ERROR_CODE_CLOSED = BiometricPrompt.ERROR_USER_CANCELED
    }
}

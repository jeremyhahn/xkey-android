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

import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * The one way the app waits for a yes/no answer from a dialog shown on an
 * activity: the wait is bound to the host's lifecycle, so it always settles.
 *
 * A dialog's window belongs to its host. When the host is destroyed (a
 * biometric screen that finishes itself as soon as its prompt is answered,
 * for example) the dialog goes with it and none of its buttons ever fire; a
 * caller waiting on those buttons would wait forever, and on the stream path
 * that caller holds the only connection. Here the host going away, or a
 * dismiss with no button answer, is a refusal.
 *
 * [build] fills in the dialog (title, message, buttons, cancelable) and wires
 * its buttons to `answer`. The wait:
 *  - returns `false` at once when the host is finishing, destroyed or not
 *    started, without showing anything;
 *  - settles once, through one idempotent settle that removes the lifecycle
 *    observer, dismisses the dialog and resumes the caller if it still waits;
 *  - settles `false` when the host is destroyed, and on a dismiss or cancel
 *    that no button answered;
 *  - on cancellation of the caller dismisses the dialog and removes the
 *    observer.
 */
internal suspend fun awaitHostedAnswer(
    host: FragmentActivity,
    build: (builder: MaterialAlertDialogBuilder, answer: (Boolean) -> Unit) -> Unit
): Boolean = withContext(Dispatchers.Main) {
    if (host.isFinishing || host.isDestroyed ||
        !host.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
    ) {
        return@withContext false
    }
    suspendCancellableCoroutine { continuation ->
        // Touched only on the main thread: settle runs there, and the
        // cancellation handler hops to it.
        var dialog: AlertDialog? = null
        var settled = false
        lateinit var observer: LifecycleEventObserver

        fun settle(answer: Boolean) {
            if (settled) return
            settled = true
            host.lifecycle.removeObserver(observer)
            dialog?.dismiss()
            if (continuation.isActive) continuation.resume(answer)
        }

        observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_DESTROY) settle(false)
        }

        val builder = MaterialAlertDialogBuilder(host)
        build(builder) { answer -> settle(answer) }
        builder
            .setOnDismissListener { settle(false) }
            .setOnCancelListener { settle(false) }

        host.lifecycle.addObserver(observer)
        dialog = builder.show()
        continuation.invokeOnCancellation { host.runOnUiThread { settle(false) } }
    }
}

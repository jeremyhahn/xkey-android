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
package com.automatethethings.xkey.media

import android.Manifest
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.os.bundleOf

/**
 * The one request-and-retry step every interactive entry point takes before
 * it reads media through [MediaPublisher.openOriginal]: signing, verifying,
 * co-signing, a Share-sheet save and the write-request screen.
 *
 * MediaStore serves an item whole, location included, only to an app that
 * holds ACCESS_MEDIA_LOCATION ([MediaPublisher.needsLocationAccess]). When
 * every URI is readable whole, [withOriginals] runs its action at once;
 * otherwise it asks for the permission and runs the action once the user
 * has answered, granted or not. Declined, the action meets
 * [MediaPublisher.OriginalUnavailableException] and reports location access
 * unavailable: the redacted view is never signed, staged or checked.
 *
 * Construct it as an activity field: the request is registered before the
 * activity starts. Whether a request is open is kept in the activity's
 * saved state, so it survives a recreation (a rotation while the dialog is
 * open): the recreated activity's calls to [withOriginals] join that open
 * request rather than asking again, and run once the user answers it. An
 * activity that resumes waiting work after a recreation does so by calling
 * [withOriginals] again from its restored state; an action only the old
 * instance held is gone with it.
 */
class MediaLocationAccess(private val activity: ComponentActivity) {

    /** The actions waiting on the open request, in call order. */
    private val waiting = mutableListOf<() -> Unit>()

    /** Whether a request is open: this instance's, or the one before a recreation. */
    private var asking = false

    /** Whether [asking] was taken from the saved state of the instance before a recreation. */
    private var restored = false

    private val launcher = activity.registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        restore()
        asking = false
        val actions = waiting.toList()
        waiting.clear()
        actions.forEach { it() }
    }

    init {
        activity.savedStateRegistry.registerSavedStateProvider(STATE_KEY) { bundleOf(KEY_ASKING to asking) }
    }

    /** Take [asking] from the instance before a recreation, once its state is restored. */
    private fun restore() {
        if (restored || !activity.savedStateRegistry.isRestored) return
        restored = true
        if (activity.savedStateRegistry.consumeRestoredStateForKey(STATE_KEY)?.getBoolean(KEY_ASKING) == true) {
            asking = true
        }
    }

    /**
     * Run [action] once [uris] are readable whole, or the user has declined to
     * make them so. While a request is open, [action] waits for its answer.
     */
    fun withOriginals(uris: Collection<Uri>, action: () -> Unit) {
        restore()
        if (asking) {
            waiting += action
            return
        }
        if (uris.none { MediaPublisher.needsLocationAccess(activity, it) }) {
            action()
            return
        }
        waiting += action
        asking = true
        launcher.launch(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    private companion object {
        const val STATE_KEY = "com.automatethethings.xkey.media.MediaLocationAccess"
        const val KEY_ASKING = "asking"
    }
}

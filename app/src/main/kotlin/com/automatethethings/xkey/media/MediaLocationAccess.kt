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
 * activity starts. An action waiting on an answer when the activity is
 * recreated is dropped, and the user starts it again.
 */
class MediaLocationAccess(private val activity: ComponentActivity) {

    private var waiting: (() -> Unit)? = null

    private val launcher = activity.registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        val action = waiting
        waiting = null
        action?.invoke()
    }

    /** Run [action] once [uris] are readable whole, or the user has declined to make them so. */
    fun withOriginals(uris: Collection<Uri>, action: () -> Unit) {
        if (uris.none { MediaPublisher.needsLocationAccess(activity, it) }) {
            action()
            return
        }
        waiting = action
        launcher.launch(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }
}

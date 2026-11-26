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
package com.automatethethings.xkey.ui

import android.content.ComponentName
import android.content.Intent
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.protocol.RemoteAttestKeyResult
import com.automatethethings.xkey.protocol.RemoteBackendInfo
import com.automatethethings.xkey.protocol.RemoteGetKeyInfoResult
import com.automatethethings.xkey.protocol.RemoteGetPublicKeyResult
import com.automatethethings.xkey.protocol.RemoteKeyInfo
import com.automatethethings.xkey.remote.DesktopPeerSession
import com.automatethethings.xkey.remote.RemoteKeyClient
import io.mockk.every
import io.mockk.mockk
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController

/**
 * Stands in for [XKeyGattService] when [DesktopKeysActivity] binds it: the
 * application shadow hands the activity a real [XKeyGattService.LocalBinder]
 * of a mocked service, whose desktop session is [peer] on [sessionClient].
 *
 * Like the real service, every [XKeyGattService.desktopSession] call returns
 * a new [DesktopPeerSession] object over the same client.
 */
class DesktopKeysTestService {
    val app = RuntimeEnvironment.getApplication()
    val component = ComponentName(app, XKeyGattService::class.java)

    val service: XKeyGattService = mockk()

    /** The client of the session the screen opens with. */
    val client: RemoteKeyClient = mockk()

    /** The confirmed peer of the session that is up, or null when none is (or it is not yet confirmed). */
    var peer: String? = PEER

    /** The client the session hands out now; replace it to model a reconnect. */
    var sessionClient: RemoteKeyClient = client

    init {
        every { service.desktopSession() } answers { peer?.let { DesktopPeerSession(it, sessionClient) } }
    }

    /** A new binder for [service], as the service hands out on each bind. */
    fun binder(): XKeyGattService.LocalBinder = service.LocalBinder()

    /** Lets the activity bind [service]; call before [start]. */
    fun register(): DesktopKeysTestService = apply {
        shadowOf(app).setComponentNameAndServiceForBindService(component, binder())
    }

    /** Makes `bindService` for the service return false; call before [start]. */
    fun refuseBind(): DesktopKeysTestService = apply {
        shadowOf(app).declareComponentUnbindable(component)
    }

    /** Starts the screen for [peerExtra] (no extra when null) and runs the main looper. */
    fun start(peerExtra: String? = PEER): ActivityController<DesktopKeysActivity> {
        val intent = peerExtra?.let { DesktopKeysActivity.intent(app, it) }
            ?: Intent(app, DesktopKeysActivity::class.java)
        resetSnackbars()
        return Robolectric.buildActivity(DesktopKeysActivity::class.java, intent).setup().also { idle() }
    }

    companion object {
        const val PEER = "a1b2c3d4"
        const val OTHER_PEER = "e5f60718"

        fun idle() = shadowOf(Looper.getMainLooper()).idle()

        /**
         * Forgets the Snackbar the process-wide SnackbarManager holds as shown or
         * queued. The manager outlives each activity and test, and its dismiss
         * timeout never fires on a paused looper, so a Snackbar left over would
         * hold back the next screen's one.
         */
        fun resetSnackbars() {
            val manager = Class.forName("com.google.android.material.snackbar.SnackbarManager")
            val instance = manager.getDeclaredMethod("getInstance").apply { isAccessible = true }.invoke(null)
            for (field in listOf("currentSnackbar", "nextSnackbar")) {
                manager.getDeclaredField(field).apply { isAccessible = true }.set(instance, null)
            }
        }

        fun backend(
            name: String = "tpm",
            type: String = "tpm2",
            hardwareBacked: Boolean = true,
            signing: Boolean = true,
            attestation: Boolean = true
        ) = RemoteBackendInfo(
            name = name, type = type, hardwareBacked = hardwareBacked, signing = signing,
            decryption = false, symmetricCrypto = false, keyAgreement = false, attestation = attestation
        )

        fun key(keyId: String = "k1", label: String = "laptop ssh", backend: String = "tpm") =
            RemoteKeyInfo(keyId, backend, "ECDSA-P256", 256, label, createdAt = 1_700_000_000L)

        fun info(keyId: String = "k1", label: String = "laptop ssh", createdAt: Long = 1_700_000_000L) =
            RemoteGetKeyInfoResult(
                keyId = keyId, backend = "tpm", algorithm = "ECDSA-P256", keySizeBits = 256, label = label,
                createdAt = createdAt, hardwareBacked = true, exportable = false
            )

        fun publicKey() = RemoteGetPublicKeyResult(publicKey = "MFkwEwYHKoZI", format = "der", algorithm = "ECDSA-P256")

        fun attestation() = RemoteAttestKeyResult(
            format = "tpm2",
            certificateChain = listOf("Y2VydDE=", "Y2VydDI="),
            attestationData = "AQIDBAU=",
            nonce = "bm9uY2U="
        )
    }
}

// Reading and driving the screen's views.

fun DesktopKeysActivity.text(id: Int): String = findViewById<TextView>(id).text.toString()

fun DesktopKeysActivity.shown(id: Int): Boolean = findViewById<View>(id).visibility == View.VISIBLE

fun DesktopKeysActivity.message(): String = text(R.id.textDesktopKeysMessage)

/** The title and subtitle of each row in the list. */
fun DesktopKeysActivity.rows(): List<Pair<String, String>> {
    val list = findViewById<ListView>(R.id.listDesktopKeys)
    return (0 until list.adapter.count).map {
        val row = list.adapter.getView(it, null, list)
        row.findViewById<TextView>(R.id.textDesktopKeyTitle).text.toString() to
            row.findViewById<TextView>(R.id.textDesktopKeySubtitle).text.toString()
    }
}

/** Taps row [position] of the list and runs the main looper. */
fun DesktopKeysActivity.tapRow(position: Int) {
    findViewById<ListView>(R.id.listDesktopKeys).performItemClick(null, position, position.toLong())
    DesktopKeysTestService.idle()
}

/** Clicks the view [id] and runs the main looper. */
fun DesktopKeysActivity.tap(id: Int) {
    findViewById<View>(id).performClick()
    DesktopKeysTestService.idle()
}

/** Presses back and runs the main looper. */
fun DesktopKeysActivity.back() {
    onBackPressedDispatcher.onBackPressed()
    DesktopKeysTestService.idle()
}

/** The action button of the Snackbar on screen, or null when none is shown. */
fun DesktopKeysActivity.snackbarAction(): Button? =
    window.decorView.findViewById(com.google.android.material.R.id.snackbar_action)

/** The text of the Snackbar on screen, or null when none is shown. */
fun DesktopKeysActivity.snackbarText(): String? =
    window.decorView.findViewById<TextView>(com.google.android.material.R.id.snackbar_text)?.text?.toString()

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

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.view.PreviewView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.qr.QrCodeScannerHelper
import com.google.android.material.snackbar.Snackbar
import org.json.JSONException
import org.json.JSONObject

class QrScannerActivity : AppCompatActivity() {

    private lateinit var scannerHelper: QrCodeScannerHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scanner)

        val previewView = findViewById<PreviewView>(R.id.previewView)

        scannerHelper = QrCodeScannerHelper(
            context = this,
            lifecycleOwner = this,
            previewView = previewView,
            onResult = { value -> onQrScanned(value) }
        )

        scannerHelper.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::scannerHelper.isInitialized) {
            scannerHelper.stop()
        }
    }

    private val payloadKind: QrPayloadKind by lazy {
        QrPayloadKind.fromExtra(intent?.getStringExtra(EXTRA_PAYLOAD_KIND))
    }

    private fun onQrScanned(value: String) {
        if (QrPayloadFilter.accepts(value, payloadKind)) {
            val resultIntent = Intent().apply {
                putExtra(EXTRA_SCANNED_URI, value)
            }
            setResult(RESULT_OK, resultIntent)
            finish()
        } else {
            runOnUiThread {
                Snackbar.make(
                    findViewById(R.id.snackbarAnchor),
                    when (payloadKind) {
                        QrPayloadKind.OTPAUTH -> R.string.oath_qr_invalid
                        QrPayloadKind.COSIGN -> R.string.cosign_qr_invalid
                    },
                    Snackbar.LENGTH_SHORT
                ).show()
                // Restart scanning for the next QR code
                scannerHelper.start()
            }
        }
    }

    companion object {
        const val EXTRA_SCANNED_URI = "scanned_uri"

        /** A [QrPayloadKind] name; absent or unknown means [QrPayloadKind.OTPAUTH]. */
        const val EXTRA_PAYLOAD_KIND = "payload_kind"
    }
}

/** The payload kind a [QrScannerActivity] caller asks for. */
enum class QrPayloadKind {
    /** An `otpauth://` URI (the default, for OATH enrolment). */
    OTPAUTH,

    /** A co-sign request or response JSON object. */
    COSIGN;

    companion object {
        /** The kind named by the intent extra; otpauth when it is absent or unknown. */
        fun fromExtra(value: String?): QrPayloadKind =
            entries.firstOrNull { it.name == value } ?: OTPAUTH
    }
}

/** Decides whether a scanned QR value is the kind the caller asked for. Pure: JVM-testable. */
object QrPayloadFilter {
    fun accepts(value: String, kind: QrPayloadKind): Boolean = when (kind) {
        QrPayloadKind.OTPAUTH -> value.startsWith("otpauth://")
        QrPayloadKind.COSIGN -> isCoSignPayload(value)
    }

    private fun isCoSignPayload(value: String): Boolean {
        val trimmed = value.trim()
        if (!trimmed.startsWith("{")) return false
        return try {
            JSONObject(trimmed).has("v")
        } catch (_: JSONException) {
            false
        }
    }
}

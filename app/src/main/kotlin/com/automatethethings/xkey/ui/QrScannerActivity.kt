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

    private fun onQrScanned(value: String) {
        if (value.startsWith("otpauth://")) {
            val resultIntent = Intent().apply {
                putExtra(EXTRA_SCANNED_URI, value)
            }
            setResult(RESULT_OK, resultIntent)
            finish()
        } else {
            runOnUiThread {
                Snackbar.make(
                    findViewById(R.id.snackbarAnchor),
                    R.string.oath_qr_invalid,
                    Snackbar.LENGTH_SHORT
                ).show()
                // Restart scanning for the next QR code
                scannerHelper.start()
            }
        }
    }

    companion object {
        const val EXTRA_SCANNED_URI = "scanned_uri"
    }
}

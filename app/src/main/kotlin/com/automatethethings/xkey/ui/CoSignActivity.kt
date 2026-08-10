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

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignerRole
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.qr.QrCodeGenerator
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.time.Instant

class CoSignActivity : AppCompatActivity() {

    private lateinit var keystoreManager: KeystoreManager
    private var selectedUri: Uri? = null
    private var currentSignatureData: ContentAuthenticityData? = null
    private lateinit var rootLayout: LinearLayout
    private lateinit var signaturesContainer: LinearLayout
    private lateinit var qrImageView: ImageView
    private lateinit var initiatorSection: LinearLayout
    private lateinit var witnessSection: LinearLayout
    private lateinit var bleSection: LinearLayout
    private lateinit var selectMediaButton: Button
    private lateinit var selectedFileText: TextView
    private lateinit var keySpinner: Spinner
    private var signingKeyIds = listOf<String>()

    private val mediaPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri?.let { onMediaSelected(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keystoreManager = KeystoreManager(this)
        buildUI()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    private fun buildUI() {
        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(
                UIHelpers.resolveThemeColor(
                    this@CoSignActivity,
                    com.google.android.material.R.attr.colorSurface
                )
            )
        }

        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Premium gradient toolbar.
        // TODO: replace with the shared PremiumToolbar.install(...) helper once it lands.
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(
                    ContextCompat.getColor(this@CoSignActivity, R.color.gradient_primary_start),
                    ContextCompat.getColor(this@CoSignActivity, R.color.gradient_primary_end)
                )
            )
        }

        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@CoSignActivity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            title = getString(R.string.cosign_title)
            setTitleTextColor(ContextCompat.getColor(this@CoSignActivity, R.color.on_primary))
            elevation = 0f
        }

        val toolbarSubtitle = TextView(this).apply {
            text = getString(R.string.cosign_subtitle)
            textSize = 14f
            setTextColor(
                UIHelpers.applyAlpha(
                    ContextCompat.getColor(this@CoSignActivity, R.color.on_primary),
                    0.85f
                )
            )
            setPadding(dpToPx(72), 0, dpToPx(16), dpToPx(12))
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(toolbarSubtitle)
        rootLayout.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(16)
            setPadding(pad, pad, pad, pad)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Select media section
        selectedFileText = TextView(this).apply {
            text = getString(R.string.cosign_no_file_selected)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            textSize = 14f
        }
        selectMediaButton = Button(this).apply {
            text = getString(R.string.cosign_select_media)
            setOnClickListener { mediaPicker.launch("image/*") }
        }
        contentPadding.addView(selectMediaButton)
        contentPadding.addView(selectedFileText)

        // Key selector
        val keyLabel = TextView(this).apply {
            text = getString(R.string.file_operation_select_key)
            textSize = 14f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(12)
            layoutParams = lp
        }
        contentPadding.addView(keyLabel)

        keySpinner = Spinner(this)
        contentPadding.addView(keySpinner)
        loadSigningKeys()

        // Existing signatures card
        val sigCard = PremiumCardFactory.createCompactCard(this).apply {
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
        }
        signaturesContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(16)
            setPadding(pad, pad, pad, pad)
        }
        val sigTitle = TextView(this).apply {
            text = getString(R.string.cosign_current_signatures)
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorPrimary))
        }
        signaturesContainer.addView(sigTitle)
        val noSigText = TextView(this).apply {
            text = getString(R.string.cosign_signature_placeholder)
            textSize = 13f
            setTextColor(paletteColor(R.color.security_neutral))
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(8)
            layoutParams = lp
        }
        signaturesContainer.addView(noSigText)
        sigCard.addView(signaturesContainer)
        contentPadding.addView(sigCard)

        // Mode selector
        val modeGroup = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
        }
        val qrRadio = RadioButton(this).apply { text = getString(R.string.cosign_mode_qr); id = View.generateViewId(); isChecked = true }
        val bleRadio = RadioButton(this).apply { text = getString(R.string.cosign_mode_ble); id = View.generateViewId() }
        modeGroup.addView(qrRadio)
        modeGroup.addView(bleRadio)
        contentPadding.addView(modeGroup)

        // Initiator section (QR)
        initiatorSection = buildInitiatorSection()
        contentPadding.addView(initiatorSection)

        // Witness section (QR)
        witnessSection = buildWitnessSection()
        witnessSection.visibility = View.GONE
        contentPadding.addView(witnessSection)

        // BLE section
        bleSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
        }
        val bleCard = MaterialCardView(this).apply {
            radius = dpToPx(12).toFloat()
            cardElevation = dpToPx(2).toFloat()
        }
        val bleContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dpToPx(24)
            setPadding(pad, pad, pad, pad)
            gravity = Gravity.CENTER
        }
        bleContent.addView(TextView(this).apply {
            text = getString(R.string.cosign_waiting_ble)
            textSize = 14f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            gravity = Gravity.CENTER
        })
        bleCard.addView(bleContent)
        bleSection.addView(bleCard)
        contentPadding.addView(bleSection)

        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            when (checkedId) {
                qrRadio.id -> {
                    initiatorSection.visibility = View.VISIBLE
                    witnessSection.visibility = View.GONE
                    bleSection.visibility = View.GONE
                }
                bleRadio.id -> {
                    initiatorSection.visibility = View.GONE
                    witnessSection.visibility = View.GONE
                    bleSection.visibility = View.VISIBLE
                }
            }
        }

        rootLayout.addView(contentPadding)
        scrollView.addView(rootLayout)
        setContentView(scrollView)
    }

    private fun buildInitiatorSection(): LinearLayout {
        val section = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
        }

        section.addView(TextView(this).apply {
            text = getString(R.string.cosign_initiator_title)
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorPrimary))
        })

        val generateQrButton = Button(this).apply {
            text = getString(R.string.cosign_generate_qr)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(8)
            layoutParams = lp
            setOnClickListener { generateInitiatorQR() }
        }
        section.addView(generateQrButton)

        qrImageView = ImageView(this).apply {
            val size = dpToPx(256)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dpToPx(12)
            }
            visibility = View.GONE
        }
        section.addView(qrImageView)

        // Button to switch to witness mode
        val switchToWitnessButton = Button(this).apply {
            text = getString(R.string.cosign_witness_title)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
            setOnClickListener {
                initiatorSection.visibility = View.GONE
                witnessSection.visibility = View.VISIBLE
            }
        }
        section.addView(switchToWitnessButton)

        return section
    }

    private fun buildWitnessSection(): LinearLayout {
        val section = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
        }

        section.addView(TextView(this).apply {
            text = getString(R.string.cosign_witness_title)
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorPrimary))
        })

        section.addView(TextView(this).apply {
            text = getString(R.string.cosign_witness_description)
            textSize = 13f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(4)
            layoutParams = lp
        })

        // Manual hash input for witness mode (simplified - in production would use QR scanner)
        val hashInput = android.widget.EditText(this).apply {
            hint = getString(R.string.cosign_hash_hint)
            textSize = 14f
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(12)
            layoutParams = lp
        }
        section.addView(hashInput)

        val witnessQrImage = ImageView(this).apply {
            val size = dpToPx(256)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dpToPx(12)
            }
            visibility = View.GONE
            tag = "witnessQr"
        }

        val signButton = Button(this).apply {
            text = getString(R.string.cosign_approve)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(8)
            layoutParams = lp
            setOnClickListener {
                val hash = hashInput.text.toString().trim()
                if (hash.isEmpty()) {
                    Snackbar.make(rootLayout, getString(R.string.cosign_hash_required), Snackbar.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                signAsWitness(hash, witnessQrImage)
            }
        }
        section.addView(signButton)
        section.addView(witnessQrImage)

        // Back to initiator button
        val backButton = Button(this).apply {
            text = getString(R.string.cosign_initiator_title)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(16)
            layoutParams = lp
            setOnClickListener {
                witnessSection.visibility = View.GONE
                initiatorSection.visibility = View.VISIBLE
            }
        }
        section.addView(backButton)

        return section
    }

    private fun onMediaSelected(uri: Uri) {
        selectedUri = uri
        selectedFileText.text = uri.lastPathSegment ?: uri.toString()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val mimeType = contentResolver.getType(uri)
                val sigData = XmpMetadataHelper.readSignatureFromUri(contentResolver, uri, mimeType)
                currentSignatureData = sigData

                withContext(Dispatchers.Main) {
                    updateSignaturesDisplay(sigData)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.cosign_read_signatures_error, e.message ?: ""),
                        Snackbar.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun updateSignaturesDisplay(data: ContentAuthenticityData?) {
        // Clear existing (keep title)
        while (signaturesContainer.childCount > 1) {
            signaturesContainer.removeViewAt(1)
        }

        if (data == null || data.signatures.isEmpty()) {
            signaturesContainer.addView(TextView(this).apply {
                text = getString(R.string.verify_no_signatures)
                textSize = 13f
                setTextColor(paletteColor(R.color.security_neutral))
            })
            return
        }

        signaturesContainer.addView(TextView(this).apply {
            text = getString(R.string.cosign_hash_preview, data.contentHash.take(16))
            textSize = 12f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            setTypeface(Typeface.MONOSPACE)
        })

        data.signatures.forEach { sig ->
            val sigView = TextView(this).apply {
                text = "${sig.role.name}: ${sig.signerName ?: sig.keyFingerprint.take(16)}... (${sig.algorithm})"
                textSize = 13f
                setTextColor(paletteColor(R.color.tertiary))
                val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                lp.topMargin = dpToPx(4)
                layoutParams = lp
            }
            signaturesContainer.addView(sigView)
        }
    }

    private fun generateInitiatorQR() {
        val data = currentSignatureData
        if (data == null) {
            Snackbar.make(rootLayout, getString(R.string.cosign_select_media_first), Snackbar.LENGTH_SHORT).show()
            return
        }

        val selectedKeyIndex = keySpinner.selectedItemPosition
        if (selectedKeyIndex < 0 || signingKeyIds.isEmpty()) {
            Snackbar.make(rootLayout, getString(R.string.file_operation_no_keys), Snackbar.LENGTH_SHORT).show()
            return
        }
        val keyId = signingKeyIds[selectedKeyIndex]
        val pubKeyDer = keystoreManager.getPublicKeyDER(keyId)
        val fingerprint = if (pubKeyDer != null) MediaHasher.hashBytes(pubKeyDer) else keyId

        val qrPayload = JSONObject().apply {
            put("v", 1)
            put("hash", data.contentHash)
            put("alg", data.hashAlgorithm)
            put("from", fingerprint)
        }.toString()

        val bitmap = QrCodeGenerator.generate(qrPayload, dpToPx(256))
        qrImageView.setImageBitmap(bitmap)
        qrImageView.visibility = View.VISIBLE

        AuditLogger.logCoSignInitiated(data.contentHash)
    }

    private fun signAsWitness(contentHash: String, qrImageView: ImageView) {
        val selectedKeyIndex = keySpinner.selectedItemPosition
        if (selectedKeyIndex < 0 || signingKeyIds.isEmpty()) {
            Snackbar.make(rootLayout, getString(R.string.file_operation_no_keys), Snackbar.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyId = signingKeyIds[selectedKeyIndex]
                val db = XKeyDatabase.getInstance(this@CoSignActivity)
                val keyEntity = db.keyDao().getByKeyId(keyId)
                    ?: throw Exception("Key not found")

                val hashBytes = contentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val signature = keystoreManager.signWithAlgorithm(keyId, hashBytes, keyEntity.algorithm)
                val signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP)

                val pubKeyDer = keystoreManager.getPublicKeyDER(keyId)
                val fingerprint = if (pubKeyDer != null) MediaHasher.hashBytes(pubKeyDer) else keyId

                val responsePayload = JSONObject().apply {
                    put("v", 1)
                    put("sig", signatureBase64)
                    put("fp", fingerprint)
                    put("name", keyEntity.label)
                    put("alg", keyEntity.algorithm)
                }.toString()

                val bitmap = QrCodeGenerator.generate(responsePayload, dpToPx(256))

                withContext(Dispatchers.Main) {
                    qrImageView.setImageBitmap(bitmap)
                    qrImageView.visibility = View.VISIBLE
                    Snackbar.make(rootLayout, getString(R.string.cosign_success), Snackbar.LENGTH_SHORT).show()
                }

                AuditLogger.logCoSignReceived(contentHash, fingerprint)

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Snackbar.make(rootLayout, getString(R.string.cosign_error, e.message ?: "Unknown"), Snackbar.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun loadSigningKeys() {
        lifecycleScope.launch(Dispatchers.IO) {
            val db = XKeyDatabase.getInstance(this@CoSignActivity)
            val keys = db.keyDao().getAll().filter {
                !it.isSystemKey && it.keyType in listOf("signing", "fido2", "tls", "ssh")
            }
            signingKeyIds = keys.map { it.keyId }
            val keyLabels = keys.map { "${it.label} (${it.algorithm})" }

            withContext(Dispatchers.Main) {
                keySpinner.adapter = ArrayAdapter(
                    this@CoSignActivity,
                    android.R.layout.simple_spinner_dropdown_item,
                    keyLabels
                )
            }
        }
    }

    private fun dpToPx(dp: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, dp.toFloat(), resources.displayMetrics).toInt()

    /**
     * Resolves a Material theme colour attribute against the current theme.
     */
    private fun resolveThemeColor(attr: Int): Int = UIHelpers.resolveThemeColor(this, attr)

    /**
     * Reads a colour from the xKey design-system palette.
     */
    private fun paletteColor(resId: Int): Int = ContextCompat.getColor(this, resId)
}

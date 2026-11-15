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

import android.content.Context
import android.content.Intent
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
import com.automatethethings.xkey.media.CoSignAppendResult
import com.automatethethings.xkey.media.CoSignParseResult
import com.automatethethings.xkey.media.CoSignPayload
import com.automatethethings.xkey.media.CoSignPayloadError
import com.automatethethings.xkey.media.CoSignRequest
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignedCopyDocument
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.qr.QrCodeGenerator
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.time.Clock
import java.util.UUID

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

    private lateinit var witnessQrImage: ImageView
    private lateinit var witnessQrLabel: TextView

    // OpenDocument, not GetContent: the owner's co-sign is written back to this Uri.
    private val mediaPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onMediaSelected(it) }
    }

    private val requestScanner = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        onScanResult(QrScanResult.from(result)) { onRequestScanned(it) }
    }

    private val responseScanner = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        onScanResult(QrScanResult.from(result)) { onResponseScanned(it) }
        responseScanFor = null
    }

    /**
     * The media, and the content hash it showed, that the open response
     * scan began for ([startResponseScan]): what the witness was shown and
     * signed. It is kept in the saved state, so a response that returns to
     * the screen after a recreation is bound to it, never to what the
     * recreated screen shows by then.
     */
    private class ScanTarget(val media: Uri, val contentHash: String)

    private var responseScanFor: ScanTarget? = null

    /**
     * Where a co-signed copy goes when the selected media cannot be replaced
     * in place: created as the media's own type, named after its display name.
     */
    private val coSignedCopyLauncher = registerForActivityResult(SignedCopyDocument.Create()) { uri ->
        onCoSignedCopyPicked(uri)
    }

    /**
     * Co-signed media waiting for the document the user picks: [staged]
     * holds it, under [MediaPublisher.recoveryDirectory], so a failed write
     * keeps it; [signerName] and [fingerprint] name the co-signer when it is
     * written.
     */
    private class PendingCoSignedCopy(
        val staged: File,
        val signerName: String,
        val fingerprint: String,
        val data: ContentAuthenticityData,
        /** The media co-signed: responses queued for it go to the copy once the copy is selected. */
        val source: Uri
    )

    private var pendingCopy: PendingCoSignedCopy? = null

    /**
     * A co-signed copy whose document the user picked, writing now. Its
     * write runs in [MediaSaveRuns], not this instance's scope, and it is
     * kept in the saved state, so the instance after a recreation waits on
     * the same write and selects [target] when it ends (after process death
     * the write runs again while [PendingCoSignedCopy.staged] remains).
     */
    private class RunningCoSignedCopy(val id: String, val target: Uri, val copy: PendingCoSignedCopy)

    private var runningCopy: RunningCoSignedCopy? = null

    /**
     * Ends once [runningCopy] has ended and its outcome is shown: a witness
     * response scanned meanwhile waits for it, so it is appended to the copy
     * holding the previous co-signature, never to the original.
     */
    private var copyShown: Job? = null

    /**
     * Witness responses scanned and not yet appended, oldest first. They are
     * kept in the saved state and each leaves only once its append has an
     * outcome, so a response scanned while a copy writes, or while one is
     * placed, survives a recreation and is appended to that copy. Each is
     * bound to the media it was scanned for ([QueuedResponse]) and is only
     * ever appended to that media ([appendQueuedResponse]).
     */
    private val queuedResponses = ArrayList<QueuedResponse>()

    /**
     * A scanned response [raw], bound to the [media] its scan began for and
     * to the [contentHash] that media showed: the hash the witness was shown
     * and signed. Either is null only when no scan began for it, or when a
     * saved state did not keep it; such a response is refused.
     */
    private class QueuedResponse(val raw: String, val media: Uri?, val contentHash: String?)

    /** An append of [queuedResponses]' head is running in this instance. */
    private var appending = false

    /**
     * The id, in [MediaSaveRuns], of the append of [queuedResponses]' head
     * once it has started. It is kept in the saved state, so the instance
     * after a recreation waits on that append rather than running it again.
     */
    private var runningAppend: String? = null

    /** The signing keys, once loaded; the request prompt waits for them after a recreation. */
    private val signingKeysLoaded = CompletableDeferred<Unit>()

    /** The key id to select once the key list loads (restored after a recreation). */
    private var pendingKeyId: String? = null

    /** The signature read of [selectedUri]; an append waits for it. */
    private var mediaLoad: Job? = null

    private fun coSignScanIntent(): Intent = Intent(this, QrScannerActivity::class.java)
        .putExtra(QrScannerActivity.EXTRA_PAYLOAD_KIND, QrPayloadKind.COSIGN.name)

    private fun onScanResult(scan: QrScanResult, onScanned: (String) -> Unit) {
        when (scan) {
            is QrScanResult.Scanned -> onScanned(scan.value)
            QrScanResult.CameraDenied ->
                Snackbar.make(rootLayout, getString(R.string.qr_camera_denied), Snackbar.LENGTH_LONG).show()
            QrScanResult.Cancelled -> Unit
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keystoreManager = KeystoreManager(this)
        // Restored before buildUI loads the keys, and before onStart delivers a
        // scan result that was pending when the previous instance went away.
        pendingKeyId = savedInstanceState?.getString(STATE_KEY_ID)
        buildUI()
        savedInstanceState?.let { restoreExchange(it) }
        runningCopy?.let { runCopy(it) }
        appendQueuedResponse()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_MEDIA_URI, selectedUri?.toString())
        outState.putBoolean(STATE_WITNESS_MODE, witnessSection.visibility == View.VISIBLE)
        outState.putString(STATE_KEY_ID, selectedKeyId() ?: pendingKeyId)
        pendingCopy?.let { saveCopy(outState, STATE_COPY_PREFIX, it) }
        runningCopy?.let {
            outState.putString(STATE_RUNNING_ID, it.id)
            outState.putString(STATE_RUNNING_TARGET, it.target.toString())
            saveCopy(outState, STATE_RUNNING_PREFIX, it.copy)
        }
        outState.putStringArrayList(STATE_QUEUED_RESPONSES, ArrayList(queuedResponses.map { it.raw }))
        outState.putStringArrayList(STATE_QUEUED_MEDIA, ArrayList(queuedResponses.map { it.media?.toString() ?: "" }))
        outState.putStringArrayList(STATE_QUEUED_HASHES, ArrayList(queuedResponses.map { it.contentHash ?: "" }))
        outState.putString(STATE_RUNNING_APPEND, runningAppend)
        responseScanFor?.let {
            outState.putString(STATE_SCAN_MEDIA, it.media.toString())
            outState.putString(STATE_SCAN_HASH, it.contentHash)
        }
    }

    private fun saveCopy(state: Bundle, prefix: String, copy: PendingCoSignedCopy) {
        state.putString(prefix + STATE_COPY_STAGED, copy.staged.path)
        state.putString(prefix + STATE_COPY_SIGNER, copy.signerName)
        state.putString(prefix + STATE_COPY_FINGERPRINT, copy.fingerprint)
        state.putString(prefix + STATE_COPY_DATA, copy.data.toJsonString())
        state.putString(prefix + STATE_COPY_SOURCE, copy.source.toString())
    }

    private fun restoreCopy(state: Bundle, prefix: String): PendingCoSignedCopy? {
        val staged = state.getString(prefix + STATE_COPY_STAGED) ?: return null
        val signer = state.getString(prefix + STATE_COPY_SIGNER) ?: return null
        val fingerprint = state.getString(prefix + STATE_COPY_FINGERPRINT) ?: return null
        val data = state.getString(prefix + STATE_COPY_DATA) ?: return null
        val source = state.getString(prefix + STATE_COPY_SOURCE) ?: return null
        return try {
            PendingCoSignedCopy(File(staged), signer, fingerprint, ContentAuthenticityData.fromJsonString(data), Uri.parse(source))
        } catch (_: Exception) {
            null
        }
    }

    private fun restoreExchange(state: Bundle) {
        pendingCopy = restoreCopy(state, STATE_COPY_PREFIX)
        val raws = state.getStringArrayList(STATE_QUEUED_RESPONSES).orEmpty()
        val media = state.getStringArrayList(STATE_QUEUED_MEDIA).orEmpty()
        val hashes = state.getStringArrayList(STATE_QUEUED_HASHES).orEmpty()
        raws.forEachIndexed { i, raw ->
            // A response whose binding was not kept is bound to no media, so it is never appended.
            val uri = media.getOrNull(i)?.takeIf { it.isNotEmpty() }?.let(Uri::parse)
            queuedResponses.add(QueuedResponse(raw, uri, hashes.getOrNull(i)?.takeIf { it.isNotEmpty() }))
        }
        runningAppend = state.getString(STATE_RUNNING_APPEND)?.takeIf { queuedResponses.isNotEmpty() }
        val scanMedia = state.getString(STATE_SCAN_MEDIA)
        val scanHash = state.getString(STATE_SCAN_HASH)
        if (scanMedia != null && scanHash != null) responseScanFor = ScanTarget(Uri.parse(scanMedia), scanHash)
        val runningId = state.getString(STATE_RUNNING_ID)
        val runningTarget = state.getString(STATE_RUNNING_TARGET)
        val running = restoreCopy(state, STATE_RUNNING_PREFIX)
        if (runningId != null && runningTarget != null && running != null) {
            runningCopy = RunningCoSignedCopy(runningId, Uri.parse(runningTarget), running)
        }
        if (state.getBoolean(STATE_WITNESS_MODE)) {
            initiatorSection.visibility = View.GONE
            witnessSection.visibility = View.VISIBLE
        }
        state.getString(STATE_MEDIA_URI)?.let { uri ->
            val restored = Uri.parse(uri)
            selectedUri = restored
            selectedFileText.text = restored.lastPathSegment ?: uri
            loadSignatures(restored)
        }
    }

    /** The key the spinner selects, or null before the key list has loaded. */
    private fun selectedKeyId(): String? {
        val index = keySpinner.selectedItemPosition
        return if (signingKeysLoaded.isCompleted && index in signingKeyIds.indices) signingKeyIds[index] else null
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
            setOnClickListener { mediaPicker.launch(XmpMetadataHelper.EMBEDDED_MIME_TYPES.toTypedArray()) }
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
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
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
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
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

        val scanResponseButton = Button(this).apply {
            text = getString(R.string.cosign_scan_response)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(8)
            layoutParams = lp
            setOnClickListener { startResponseScan() }
        }
        section.addView(scanResponseButton)

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
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
        })

        section.addView(TextView(this).apply {
            text = getString(R.string.cosign_witness_description)
            textSize = 13f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(4)
            layoutParams = lp
        })

        val scanRequestButton = Button(this).apply {
            text = getString(R.string.cosign_scan_request)
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(12)
            layoutParams = lp
            setOnClickListener { requestScanner.launch(coSignScanIntent()) }
        }
        section.addView(scanRequestButton)

        witnessQrLabel = TextView(this).apply {
            text = getString(R.string.cosign_show_response)
            textSize = 13f
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            gravity = Gravity.CENTER_HORIZONTAL
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dpToPx(12)
            layoutParams = lp
            visibility = View.GONE
        }
        section.addView(witnessQrLabel)

        witnessQrImage = ImageView(this).apply {
            val size = dpToPx(256)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dpToPx(8)
            }
            visibility = View.GONE
            tag = "witnessQr"
        }
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
        currentSignatureData = null
        // Responses scanned for other media are never appended to this one
        // (appendQueuedResponse refuses them); refuse those waiting now.
        appendQueuedResponse()
        qrImageView.visibility = View.GONE
        selectedFileText.text = uri.lastPathSegment ?: uri.toString()

        try {
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } catch (_: SecurityException) {
            // The provider grants no persistable permission; the session grant still covers this screen.
        }

        loadSignatures(uri)
    }

    /** Reads the media's signature data into [currentSignatureData] and the card. */
    private fun loadSignatures(uri: Uri) {
        mediaLoad = lifecycleScope.launch(Dispatchers.IO) {
            try {
                val mimeType = contentResolver.getType(uri)
                val sigData = XmpMetadataHelper.readSignatureFromUri(contentResolver, uri, mimeType)
                currentSignatureData = sigData

                withContext(Dispatchers.Main) {
                    updateSignaturesDisplay(sigData)
                    if (sigData == null) {
                        Snackbar.make(rootLayout, getString(R.string.cosign_no_signature_data), Snackbar.LENGTH_LONG).show()
                    }
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
            val message = if (selectedUri == null) R.string.cosign_select_media_first else R.string.cosign_no_signature_data
            Snackbar.make(rootLayout, getString(message), Snackbar.LENGTH_SHORT).show()
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

        val qrPayload = CoSignRequest.of(data, fingerprint).toJsonString()

        val bitmap = QrCodeGenerator.generate(qrPayload, dpToPx(256))
        qrImageView.setImageBitmap(bitmap)
        qrImageView.visibility = View.VISIBLE

        AuditLogger.logCoSignInitiated(data.contentHash)
    }

    private fun signAsWitness(request: CoSignRequest, keyId: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val db = XKeyDatabase.getInstance(this@CoSignActivity)
                val keyEntity = db.keyDao().getByKeyId(keyId)
                    ?: throw Exception("Key not found")

                val signature = keystoreManager.signWithAlgorithm(keyId, request.hashBytes(), keyEntity.algorithm)
                val signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP)

                val pubKeyDer = keystoreManager.getPublicKeyDER(keyId)
                val fingerprint = if (pubKeyDer != null) MediaHasher.hashBytes(pubKeyDer) else keyId

                val responsePayload = CoSignResponse(
                    signature = signatureBase64,
                    fingerprint = fingerprint,
                    signerName = keyEntity.label,
                    algorithm = keyEntity.algorithm
                ).toJsonString()

                val bitmap = QrCodeGenerator.generate(responsePayload, dpToPx(256))

                withContext(Dispatchers.Main) {
                    witnessQrImage.setImageBitmap(bitmap)
                    witnessQrImage.visibility = View.VISIBLE
                    witnessQrLabel.visibility = View.VISIBLE
                    Snackbar.make(rootLayout, getString(R.string.cosign_success), Snackbar.LENGTH_SHORT).show()
                }

                AuditLogger.logCoSignReceived(request.contentHash, fingerprint)

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Snackbar.make(rootLayout, getString(R.string.cosign_error, e.message ?: "Unknown"), Snackbar.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Witness side: a scanned request QR is shown with its content hash and the
     * owner's fingerprint; the witness signs only after approving.
     */
    private fun onRequestScanned(raw: String) {
        val request = when (val parsed = CoSignPayload.parseRequest(raw)) {
            is CoSignParseResult.Ok -> parsed.value
            is CoSignParseResult.Failed -> {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.cosign_request_refused, payloadErrorText(parsed.error)),
                    Snackbar.LENGTH_LONG
                ).show()
                return
            }
        }

        // After a recreation the result arrives before the key list reloads.
        lifecycleScope.launch {
            signingKeysLoaded.await()
            val keyId = selectedKeyId()
            if (keyId == null) {
                Snackbar.make(rootLayout, getString(R.string.file_operation_no_keys), Snackbar.LENGTH_SHORT).show()
                return@launch
            }
            val keyLabel = keySpinner.selectedItem?.toString() ?: keyId
            promptWitnessApproval(request, keyId, keyLabel)
        }
    }

    private fun promptWitnessApproval(request: CoSignRequest, keyId: String, keyLabel: String) {
        witnessQrImage.visibility = View.GONE
        witnessQrLabel.visibility = View.GONE

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.cosign_approve_title)
            .setMessage(
                getString(
                    R.string.cosign_approve_request_message,
                    keyLabel,
                    request.hashAlgorithm,
                    request.contentHash,
                    request.ownerFingerprint
                )
            )
            .setPositiveButton(R.string.cosign_approve) { _, _ -> signAsWitness(request, keyId) }
            .setNegativeButton(R.string.cosign_deny, null)
            .show()
    }

    /**
     * Opens the scanner for a witness's response to the selected media,
     * first recording ([responseScanFor]) that media and the hash it shows:
     * the one place a response scan begins.
     */
    private fun startResponseScan() {
        val media = selectedUri
        // currentSignatureData is cleared on every media change, so it is this media's.
        val hash = currentSignatureData?.contentHash
        if (media == null || hash == null) {
            Snackbar.make(rootLayout, getString(R.string.cosign_select_media_first), Snackbar.LENGTH_SHORT).show()
            return
        }
        responseScanFor = ScanTarget(media, hash)
        responseScanner.launch(coSignScanIntent())
    }

    /**
     * Owner side: a scanned response QR becomes an ATTESTOR entry appended to
     * the media its scan began for, unless its key has already signed. It is
     * queued ([queuedResponses]), bound to that media and the hash it showed
     * ([responseScanFor]), and appended in turn; with no scan begun there is
     * nothing to bind it to, and it is refused.
     */
    private fun onResponseScanned(raw: String) {
        val scanFor = responseScanFor
        queuedResponses.add(QueuedResponse(raw, scanFor?.media, scanFor?.contentHash))
        appendQueuedResponse()
    }

    /**
     * Appends the oldest queued response, once nothing else is: a co-signed
     * copy still to be placed or still writing becomes the selected media when
     * it ends, so the response waits and is appended to it, keeping its
     * co-signature. The response leaves the queue only with its outcome.
     *
     * The one place an append starts: a response is appended only to the
     * media it was scanned for (and [appendToMedia] checks that media's hash),
     * and an append already running ([runningAppend]) is waited on, never
     * run again.
     */
    private fun appendQueuedResponse() {
        if (appending || pendingCopy != null || runningCopy != null) return
        val queued = queuedResponses.firstOrNull() ?: return
        val started = runningAppend
        if (started != null && MediaSaveRuns.hasFinished(started)) {
            // The instance before this one showed the outcome after its state was saved.
            runningAppend = null
            queuedResponses.removeAt(0)
            appendQueuedResponse()
            return
        }
        // Only the Uri: after a recreation the signature data is still reloading,
        // and the append reads the file's own data anyway. An append already
        // started goes on with the media it started on.
        val target = queued.media
        val expectedHash = queued.contentHash
        val refusal = when {
            target == null -> getString(R.string.cosign_select_media_first)
            // Never appended unchecked: the media must still show what the witness signed.
            expectedHash == null -> getString(R.string.cosign_response_refused, getString(R.string.cosign_error_no_hash))
            started == null && target != selectedUri ->
                getString(R.string.cosign_response_refused, getString(R.string.cosign_error_media_changed))
            else -> null
        }
        val parsed = if (refusal == null) CoSignPayload.parseResponse(queued.raw) else null
        val response = (parsed as? CoSignParseResult.Ok)?.value
        if (response == null || target == null || expectedHash == null) {
            val text = refusal ?: getString(
                R.string.cosign_response_refused,
                payloadErrorText((parsed as CoSignParseResult.Failed).error)
            )
            runningAppend = null
            queuedResponses.removeAt(0)
            Snackbar.make(rootLayout, text, Snackbar.LENGTH_LONG).show()
            appendQueuedResponse()
            return
        }
        val id = started ?: UUID.randomUUID().toString()
        runningAppend = id
        appending = true
        val pendingLoad = mediaLoad
        val context = applicationContext

        lifecycleScope.launch {
            // A reload that finished after the append would show the old signatures.
            pendingLoad?.join()
            // Run in the process, not this instance: the next instance waits on it.
            val run = MediaSaveRuns.attach(id) {
                val entry = response.toAttestorEntry(Clock.systemUTC())
                val outcome = appendToMedia(context, target, entry, expectedHash)
                // A copy is audited once it is written (runCopy).
                if (outcome is CoSignOutcome.Replaced) {
                    AuditLogger.logCoSignReceived(outcome.data.contentHash, entry.keyFingerprint)
                }
                outcome
            }
            // Throws if this instance went away first, even after the append
            // ended: the next one takes its result (a copy to place included).
            val outcome = MediaSaveRuns.outcome(run)
            val result: Any = outcome.getOrElse { it }
            MediaSaveRuns.finished(id)
            runningAppend = null
            appending = false
            queuedResponses.removeAt(0)
            when (result) {
                is CoSignOutcome.Replaced -> showAppended(result.data, response.signerName)
                is CoSignOutcome.NeedsCopy -> launchCopyPicker(
                    PendingCoSignedCopy(result.staged, response.signerName, response.fingerprint, result.data, target)
                )
                is CoSignOutcome.Duplicate -> {
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.cosign_duplicate_signer, result.fingerprint.take(16)),
                        Snackbar.LENGTH_LONG
                    ).show()
                }
                is Throwable -> showAppendFailed(result)
            }
            appendQueuedResponse()
        }
    }

    /**
     * The one place the co-signed copy's picker opens. A failure building its
     * input or launching it goes through the append's error path and leaves
     * nothing pending: the staged copy is deleted (the media it co-signs is
     * untouched) and the next response goes on.
     */
    private fun launchCopyPicker(copy: PendingCoSignedCopy) {
        pendingCopy = copy
        try {
            coSignedCopyLauncher.launch(SignedCopyDocument.of(contentResolver, copy.source, "cosigned"))
        } catch (e: Exception) {
            pendingCopy = null
            copy.staged.delete()
            showAppendFailed(e)
        }
    }

    private fun showAppended(data: ContentAuthenticityData, signerName: String) {
        currentSignatureData = data
        updateSignaturesDisplay(data)
        Snackbar.make(rootLayout, getString(R.string.cosign_appended, signerName), Snackbar.LENGTH_SHORT).show()
    }

    private fun showAppendFailed(e: Throwable) {
        Snackbar.make(
            rootLayout,
            getString(R.string.cosign_append_failed, e.message ?: e.javaClass.simpleName),
            Snackbar.LENGTH_LONG
        ).show()
    }

    /** What co-signing the selected media did. */
    private sealed class CoSignOutcome {
        /** The media was replaced atomically by its co-signed form. */
        class Replaced(val data: ContentAuthenticityData) : CoSignOutcome()

        /** The media's provider cannot replace it atomically: [staged] holds the co-signed copy, the media is untouched. */
        class NeedsCopy(val data: ContentAuthenticityData, val staged: File) : CoSignOutcome()

        /** [fingerprint] has already signed; nothing was written. */
        class Duplicate(val fingerprint: String) : CoSignOutcome()
    }

    /**
     * Appends [entry] to the media at [uri], never truncating it: the media
     * is copied to a staging file under [MediaPublisher.recoveryDirectory],
     * its own signature data is checked for a duplicate signer, the entry is
     * appended there, and the result replaces [uri] atomically where its
     * provider allows ([MediaPublisher.replace]). Anywhere else the staged
     * file is returned for a separate copy the user places. A duplicate, or
     * a failure before publication, deletes the staged file; a failed
     * publication keeps it and the [com.automatethethings.xkey.media.MediaPublishException] names it.
     *
     * Media whose content hash is not [expectedHash], the hash the witness
     * signed, is refused before anything is written. It runs
     * in [MediaSaveRuns], so it holds only the application [context].
     */
    private fun appendToMedia(context: Context, uri: Uri, entry: SignatureEntry, expectedHash: String): CoSignOutcome {
        val contentResolver = context.contentResolver
        // Typed like the media, so the copy is read and written in the same
        // container (EXIF or XMP) loadSignatures read it from.
        val suffix = XmpMetadataHelper.stagingSuffix(contentResolver.getType(uri))
        val staged = File.createTempFile("cosign-", suffix, MediaPublisher.recoveryDirectory(context))
        var handed = false
        try {
            val input = contentResolver.openInputStream(uri)
                ?: throw IOException("cannot read the selected media")
            input.use { src -> staged.outputStream().use { dst -> src.copyTo(dst) } }

            val existing = XmpMetadataHelper.readSignature(staged.absolutePath)
                ?: throw IllegalStateException(context.getString(R.string.cosign_no_signature_data))
            if (!existing.contentHash.equals(expectedHash, ignoreCase = true)) {
                throw IllegalStateException(context.getString(R.string.cosign_error_media_changed))
            }
            val result = CoSignPayload.appendAttestor(existing, entry)
            if (result is CoSignAppendResult.DuplicateSigner) return CoSignOutcome.Duplicate(result.fingerprint)
            val data = (result as CoSignAppendResult.Appended).data
            XmpMetadataHelper.appendSignature(staged.absolutePath, entry)
            handed = true
            return if (MediaPublisher.replace(uri, staged)) CoSignOutcome.Replaced(data) else CoSignOutcome.NeedsCopy(data, staged)
        } finally {
            if (!handed) staged.delete()
        }
    }

    /**
     * The document for the co-signed copy: the staged copy is written there
     * ([MediaPublisher.writeCopy]) and, once written and closed, deleted;
     * the copy becomes the selected media. A failure keeps it and names it;
     * a cancel drops it. The original is only ever read. A failure starting
     * the write goes through the append's error path and leaves nothing
     * pending or running.
     */
    private fun onCoSignedCopyPicked(target: Uri?) {
        val pending = pendingCopy ?: return
        pendingCopy = null
        if (target == null) {
            pending.staged.delete()
            appendQueuedResponse()
            return
        }
        try {
            runCopy(RunningCoSignedCopy(UUID.randomUUID().toString(), target, pending))
        } catch (e: Exception) {
            runningCopy = null
            copyShown?.cancel()
            showAppendFailed(e)
            appendQueuedResponse()
        }
    }

    /**
     * Run [run], or wait on it when it already runs (this instance restored
     * it after a recreation). It ends by selecting the copy and showing its
     * signatures, or by naming the kept bytes; an instance that goes first
     * leaves the write and its outcome to the next.
     */
    private fun runCopy(run: RunningCoSignedCopy) {
        runningCopy = run
        val resolver = applicationContext.contentResolver
        val copy = run.copy
        val write = MediaSaveRuns.attach(run.id) {
            // Gone only once written and closed: a write before process death.
            if (!copy.staged.exists()) return@attach
            MediaPublisher.writeCopy(copy.staged) { MediaPublisher.openCreated(resolver, run.target) }
            AuditLogger.logCoSignReceived(copy.data.contentHash, copy.fingerprint)
        }
        copyShown = lifecycleScope.launch {
            // Throws if this instance went away first: the next one waits on the write.
            val failure = MediaSaveRuns.outcome(write).exceptionOrNull()
            // A read of the original that ended later would show its old
            // signatures. Until the copy is installed it stays the running
            // copy, so a recreation meanwhile still selects it.
            if (failure == null) mediaLoad?.join()
            MediaSaveRuns.finished(run.id)
            runningCopy = null
            if (failure == null) {
                // Responses scanned for the co-signed media go to its copy, which
                // carries the same content (and hash) and replaces it as the selection.
                queuedResponses.replaceAll { q ->
                    if (q.media == copy.source) QueuedResponse(q.raw, run.target, q.contentHash) else q
                }
                selectedUri = run.target
                selectedFileText.text = run.target.lastPathSegment ?: run.target.toString()
                showAppended(copy.data, copy.signerName)
            } else {
                showAppendFailed(failure)
            }
            appendQueuedResponse()
        }
    }

    private fun payloadErrorText(error: CoSignPayloadError): String = when (error) {
        CoSignPayloadError.NotJson -> getString(R.string.cosign_error_not_json)
        is CoSignPayloadError.UnsupportedVersion -> getString(R.string.cosign_error_version)
        is CoSignPayloadError.MissingField -> getString(R.string.cosign_error_missing_field, error.field)
        is CoSignPayloadError.UnsupportedHashAlgorithm -> getString(R.string.cosign_error_hash_algorithm, error.algorithm)
        CoSignPayloadError.InvalidHash -> getString(R.string.cosign_error_hash)
        CoSignPayloadError.InvalidSignature -> getString(R.string.cosign_error_signature)
    }

    private fun loadSigningKeys() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val db = XKeyDatabase.getInstance(this@CoSignActivity)
                val keys = db.keyDao().getAll().filter {
                    !it.isSystemKey && it.keyType in listOf("signing", "fido2", "tls", "ssh")
                }
                val keyIds = keys.map { it.keyId }
                val keyLabels = keys.map { "${it.label} (${it.algorithm})" }

                withContext(Dispatchers.Main) {
                    signingKeyIds = keyIds
                    keySpinner.adapter = ArrayAdapter(
                        this@CoSignActivity,
                        android.R.layout.simple_spinner_dropdown_item,
                        keyLabels
                    )
                    // The key chosen before a recreation, if it still exists.
                    pendingKeyId?.let { id -> keyIds.indexOf(id).takeIf { it >= 0 }?.let(keySpinner::setSelection) }
                    pendingKeyId = null
                }
            } finally {
                signingKeysLoaded.complete(Unit)
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

    private companion object {
        const val STATE_MEDIA_URI = "cosign_media_uri"
        const val STATE_COPY_PREFIX = "cosign_pending_"
        const val STATE_RUNNING_PREFIX = "cosign_running_"
        const val STATE_RUNNING_ID = "cosign_running_id"
        const val STATE_RUNNING_TARGET = "cosign_running_target"
        const val STATE_COPY_STAGED = "cosign_copy_staged"
        const val STATE_COPY_SIGNER = "cosign_copy_signer"
        const val STATE_COPY_DATA = "cosign_copy_data"
        const val STATE_COPY_FINGERPRINT = "cosign_copy_fingerprint"
        const val STATE_COPY_SOURCE = "cosign_copy_source"
        const val STATE_QUEUED_RESPONSES = "cosign_queued_responses"
        const val STATE_QUEUED_MEDIA = "cosign_queued_media"
        const val STATE_QUEUED_HASHES = "cosign_queued_hashes"
        const val STATE_RUNNING_APPEND = "cosign_running_append"
        const val STATE_SCAN_MEDIA = "cosign_scan_media"
        const val STATE_SCAN_HASH = "cosign_scan_hash"
        const val STATE_WITNESS_MODE = "cosign_witness_mode"
        const val STATE_KEY_ID = "cosign_key_id"
    }
}

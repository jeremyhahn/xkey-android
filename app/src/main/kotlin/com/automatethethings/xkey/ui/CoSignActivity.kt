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

import android.content.ContentResolver
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
import com.automatethethings.xkey.media.MediaPublishException
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignatureVerifier
import com.automatethethings.xkey.media.SignedCopyDocument
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.qr.QrCodeGenerator
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.time.Clock
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/**
 * The media, and the content hash it showed, that a response scan began
 * for: what the witness was shown and signed.
 */
internal data class ScanTarget(val media: Uri, val contentHash: String)

/**
 * A scanned response [raw], bound to the [media] its scan began for and to
 * the [contentHash] that media showed: the hash the witness was shown and
 * signed. Either is null only when no scan began for it; such a response is
 * refused.
 */
internal data class QueuedResponse(val raw: String, val media: Uri?, val contentHash: String?)

/**
 * Co-signed media waiting for the document the user picks: [staged] holds
 * it, under [MediaPublisher.recoveryDirectory], so a failed write keeps it;
 * [signerName] and [fingerprint] name the co-signer when it is written.
 */
internal data class PendingCoSignedCopy(
    val staged: File,
    val signerName: String,
    val fingerprint: String,
    val data: ContentAuthenticityData,
    /** The media co-signed: once the copy is written, what was bound to it is bound to the copy. */
    val source: Uri
)

/**
 * A co-signed copy whose document ([target]) the user picked, writing now.
 * Its write runs in [MediaSaveRuns], not a screen's scope, so the instance
 * after a recreation waits on the same write (after process death the write
 * runs again while [PendingCoSignedCopy.staged] remains).
 */
internal data class RunningCoSignedCopy(val id: String, val target: Uri, val copy: PendingCoSignedCopy)

/**
 * Whether the document at [target] holds [copy]: every entry of [copy]'s
 * signatures is there unchanged, its payload hashes, as the signer hashes
 * it, to the co-signed content, its recorded hash is that hash, and its
 * entry by the co-signer verifies with the key [publicKeyFor] knows for the
 * co-signer's fingerprint ([SignatureVerifier.verifyCarried]). A copy whose
 * staged bytes are gone counts as written only then, so a lost or altered
 * copy, or one that lost an earlier signer's entry, is never reported as
 * placed, and an unknown co-signer's never is.
 */
internal fun copyInPlace(
    resolver: ContentResolver,
    target: Uri,
    copy: PendingCoSignedCopy,
    publicKeyFor: (fingerprint: String) -> ByteArray?
): Boolean = try {
    val mimeType = resolver.getType(target)
    val carried = XmpMetadataHelper.readSignatureFromUri(resolver, target, mimeType)
    carried != null &&
        // Every entry the copy was written with is still there, unchanged:
        // an earlier signer's dropped or altered entry is not this copy.
        copy.data.signatures.all { it in carried.signatures } &&
        SignatureVerifier.verifyCarried(
            carried,
            MediaHasher.hashStreamed(
                { resolver.openInputStream(target) ?: throw IOException("cannot read $target") },
                mimeType
            ).canonical,
            copy.data.contentHash,
            copy.fingerprint,
            publicKeyFor(copy.fingerprint)
        )
} catch (e: Exception) {
    false
}

/**
 * The public key xKey holds for [fingerprint]: a contact's, else a local
 * key's whose own hash is [fingerprint]. Suspends on the database.
 */
internal suspend fun knownPublicKey(context: Context, fingerprint: String): ByteArray? {
    val db = XKeyDatabase.getInstance(context)
    return db.contactDao().getByFingerprint(fingerprint)?.publicKeyDer
        ?: db.keyDao().getAll().firstNotNullOfOrNull { key ->
            key.publicKeyDer?.takeIf { MediaHasher.hashBytes(it) == fingerprint }
        }
}

/**
 * Everything a co-sign exchange holds that must outlive the screen showing
 * it: the selected [media], the open response [scan], the responses
 * [queued] and not yet appended (oldest first), the id in [MediaSaveRuns]
 * of the head's append once it started ([runningAppend]), the co-signed
 * copy waiting for its document ([pendingCopy]) and the copy writing
 * ([runningCopy]).
 *
 * One immutable record: the screen saves and restores it whole
 * ([toJson], [fromJson]) and changes it only through [on], so no part of it
 * is ever restored out of step with another. A copy, once written, takes
 * the place of the media it co-signed in every part that names it
 * ([rebind]).
 */
internal data class CoSignExchange(
    val media: Uri? = null,
    val scan: ScanTarget? = null,
    val queued: List<QueuedResponse> = emptyList(),
    val runningAppend: String? = null,
    val pendingCopy: PendingCoSignedCopy? = null,
    val runningCopy: RunningCoSignedCopy? = null
) {
    /** What happens to an exchange. */
    sealed class Event {
        /** A restored exchange replaces this one. */
        class Restored(val exchange: CoSignExchange) : Event()

        class MediaSelected(val uri: Uri) : Event()

        /** A response scan opens for [target]. */
        class ScanStarted(val target: ScanTarget) : Event()

        /** The open scan returned [raw], queued bound to what the scan began for, or nothing. */
        class ScanEnded(val raw: String?) : Event()

        /** The head of the queue's append starts as run [id]. */
        class AppendStarted(val id: String) : Event()

        /** The head of the queue has its outcome and leaves; [copy] is a co-signed copy to place. */
        class AppendEnded(val copy: PendingCoSignedCopy?) : Event()

        /** The copy to place goes to the document the user picked. */
        class CopyStarted(val run: RunningCoSignedCopy) : Event()

        /** The copy to place is dropped: no document was picked, or none could be. */
        object CopyDropped : Event()

        /** The copy's write ended; once [written], the copy takes the co-signed media's place. */
        class CopyEnded(val written: Boolean) : Event()
    }

    /** This exchange after [event]. */
    fun on(event: Event): CoSignExchange = when (event) {
        is Event.Restored -> event.exchange
        is Event.MediaSelected -> copy(media = event.uri)
        is Event.ScanStarted -> copy(scan = event.target)
        is Event.ScanEnded -> copy(
            scan = null,
            queued = if (event.raw == null) queued else queued + QueuedResponse(event.raw, scan?.media, scan?.contentHash)
        )
        is Event.AppendStarted -> copy(runningAppend = event.id)
        is Event.AppendEnded -> copy(
            queued = queued.drop(1),
            runningAppend = null,
            pendingCopy = event.copy ?: pendingCopy
        )
        is Event.CopyStarted -> copy(pendingCopy = null, runningCopy = event.run)
        Event.CopyDropped -> copy(pendingCopy = null)
        is Event.CopyEnded -> {
            val run = runningCopy
            val ended = copy(runningCopy = null)
            if (event.written && run != null) ended.rebind(run.copy.source, run.target) else ended
        }
    }

    /**
     * This exchange with every Uri that is [from] made [to]: the selection,
     * the open scan, each queued response and each copy's source. A copy
     * carries its source's content (and hash), so what was bound to the
     * source goes to it. Built field by field, so a new Uri field must be
     * named here.
     */
    fun rebind(from: Uri, to: Uri): CoSignExchange {
        fun Uri.moved() = if (this == from) to else this
        return CoSignExchange(
            media = media?.moved(),
            scan = scan?.let { it.copy(media = it.media.moved()) },
            queued = queued.map { it.copy(media = it.media?.moved()) },
            runningAppend = runningAppend,
            pendingCopy = pendingCopy?.let { it.copy(source = it.source.moved()) },
            runningCopy = runningCopy?.let { it.copy(target = it.target.moved(), copy = it.copy.copy(source = it.copy.source.moved())) }
        )
    }

    /** The whole exchange, for a saved state. */
    fun toJson(): String = JSONObject().apply {
        putOpt("media", media?.toString())
        scan?.let { put("scan", JSONObject().put("media", it.media.toString()).put("hash", it.contentHash)) }
        put("queued", JSONArray().apply {
            queued.forEach { q -> put(JSONObject().put("raw", q.raw).putOpt("media", q.media?.toString()).putOpt("hash", q.contentHash)) }
        })
        putOpt("runningAppend", runningAppend)
        pendingCopy?.let { put("pendingCopy", copyJson(it)) }
        runningCopy?.let { put("runningCopy", JSONObject().put("id", it.id).put("target", it.target.toString()).put("copy", copyJson(it.copy))) }
    }.toString()

    companion object {
        private fun copyJson(copy: PendingCoSignedCopy): JSONObject = JSONObject()
            .put("staged", copy.staged.path)
            .put("signer", copy.signerName)
            .put("fingerprint", copy.fingerprint)
            .put("data", copy.data.toJsonString())
            .put("source", copy.source.toString())

        private fun copyFrom(json: JSONObject): PendingCoSignedCopy = PendingCoSignedCopy(
            File(json.getString("staged")),
            json.getString("signer"),
            json.getString("fingerprint"),
            ContentAuthenticityData.fromJsonString(json.getString("data")),
            Uri.parse(json.getString("source"))
        )

        private fun JSONObject.uri(name: String): Uri? = optString(name).takeIf { has(name) && it.isNotEmpty() }?.let(Uri::parse)

        /** The exchange [toJson] saved; one that cannot be read whole is none. */
        fun fromJson(text: String): CoSignExchange = try {
            val json = JSONObject(text)
            val queued = json.optJSONArray("queued")?.let { list ->
                (0 until list.length()).map { i ->
                    val q = list.getJSONObject(i)
                    QueuedResponse(q.getString("raw"), q.uri("media"), q.optString("hash").takeIf { q.has("hash") && it.isNotEmpty() })
                }
            }.orEmpty()
            CoSignExchange(
                media = json.uri("media"),
                scan = json.optJSONObject("scan")?.let { ScanTarget(Uri.parse(it.getString("media")), it.getString("hash")) },
                queued = queued,
                // An append is only ever of the queue's head.
                runningAppend = json.optString("runningAppend").takeIf { json.has("runningAppend") && queued.isNotEmpty() },
                pendingCopy = json.optJSONObject("pendingCopy")?.let(::copyFrom),
                runningCopy = json.optJSONObject("runningCopy")?.let {
                    RunningCoSignedCopy(it.getString("id"), Uri.parse(it.getString("target")), copyFrom(it.getJSONObject("copy")))
                }
            )
        } catch (_: Exception) {
            CoSignExchange()
        }
    }
}

class CoSignActivity : AppCompatActivity() {

    private lateinit var keystoreManager: KeystoreManager
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
        val scan = QrScanResult.from(result)
        // A scan that returns nothing ends too, binding nothing.
        if (scan !is QrScanResult.Scanned) transition(CoSignExchange.Event.ScanEnded(null))
        onScanResult(scan) { onResponseScanned(it) }
    }

    /**
     * Where a co-signed copy goes when the selected media cannot be replaced
     * in place: created as the media's own type, named after its display name.
     */
    private val coSignedCopyLauncher = registerForActivityResult(SignedCopyDocument.Create()) { uri ->
        onCoSignedCopyPicked(uri)
    }

    /**
     * The exchange: the selected media, the open response scan, the
     * responses waiting, the running append and the co-signed copy to place
     * or writing. Saved and restored whole, and replaced only in
     * [transition].
     */
    private var exchange = CoSignExchange()

    /** The one place [exchange] changes. */
    private fun transition(event: CoSignExchange.Event) {
        exchange = exchange.on(event)
    }

    /**
     * Ends once the running copy has ended and its outcome is shown: a
     * witness response scanned meanwhile waits for it, so it is appended to
     * the copy holding the previous co-signature, never to the original.
     */
    private var copyShown: Job? = null

    /** This instance waits on the append of the queue's head. */
    private var appending = false

    /** The signing keys, once loaded; the request prompt waits for them after a recreation. */
    private val signingKeysLoaded = CompletableDeferred<Unit>()

    /** The key id to select once the key list loads (restored after a recreation). */
    private var pendingKeyId: String? = null

    /** The signature read of the exchange's media; an append waits for it. */
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
        // Staged copies an earlier process left: their runs died with it. One
        // the restored exchange still names (its picker was open when the
        // process died) stays until that exchange ends; one a screen not yet
        // restored may name stays for MediaSaveRuns.STAGED_RETENTION_MS.
        MediaSaveRuns.sweep(
            MediaPublisher.recoveryDirectory(applicationContext),
            keep = listOfNotNull(exchange.pendingCopy?.staged, exchange.runningCopy?.copy?.staged)
        )
        exchange.runningCopy?.let { runCopy(it) }
        appendQueuedResponse()
    }

    override fun onDestroy() {
        // Gone for good (Back, finish), not recreated: no instance takes its runs.
        if (isFinishing && !isChangingConfigurations) abandonRuns()
        super.onDestroy()
    }

    /**
     * Hand this exchange's runs to [MediaSaveRuns.abandon] and drop what
     * no screen will place: a co-signed copy an append stages after this
     * screen went, one staged for a picker that will not return, and the
     * bytes a failed copy kept. A copy writing to the document the user
     * picked finishes its write.
     */
    private fun abandonRuns() {
        val state = exchange
        state.runningAppend?.let { id ->
            MediaSaveRuns.abandon<Any?>(id) { result ->
                (result.getOrNull() as? CoSignOutcome.NeedsCopy)?.staged?.delete()
                (result.exceptionOrNull() as? MediaPublishException)?.kept?.delete()
            }
        }
        state.pendingCopy?.staged?.delete()
        state.runningCopy?.let { run ->
            MediaSaveRuns.abandon<Unit>(run.id) { result ->
                if (result.isFailure) run.copy.staged.delete()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_WITNESS_MODE, witnessSection.visibility == View.VISIBLE)
        outState.putString(STATE_KEY_ID, selectedKeyId() ?: pendingKeyId)
        outState.putString(STATE_EXCHANGE, exchange.toJson())
        // This state names these staged copies: a later process keeps them
        // until this screen is restored and adopts them.
        MediaSaveRuns.hold(listOfNotNull(exchange.pendingCopy?.staged, exchange.runningCopy?.copy?.staged))
    }

    private fun restoreExchange(state: Bundle) {
        state.getString(STATE_EXCHANGE)?.let { transition(CoSignExchange.Event.Restored(CoSignExchange.fromJson(it))) }
        if (state.getBoolean(STATE_WITNESS_MODE)) {
            initiatorSection.visibility = View.GONE
            witnessSection.visibility = View.VISIBLE
        }
        exchange.media?.let { restored ->
            selectedFileText.text = restored.lastPathSegment ?: restored.toString()
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
        transition(CoSignExchange.Event.MediaSelected(uri))
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
            val message = if (exchange.media == null) R.string.cosign_select_media_first else R.string.cosign_no_signature_data
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
     * first recording in the exchange ([CoSignExchange.Event.ScanStarted])
     * that media and the hash it shows: the one place a response scan begins.
     */
    private fun startResponseScan() {
        val media = exchange.media
        // currentSignatureData is cleared on every media change, so it is this media's.
        val hash = currentSignatureData?.contentHash
        if (media == null || hash == null) {
            Snackbar.make(rootLayout, getString(R.string.cosign_select_media_first), Snackbar.LENGTH_SHORT).show()
            return
        }
        transition(CoSignExchange.Event.ScanStarted(ScanTarget(media, hash)))
        responseScanner.launch(coSignScanIntent())
    }

    /**
     * Owner side: a scanned response QR becomes an ATTESTOR entry appended to
     * the media its scan began for, unless its key has already signed. It is
     * queued bound to that media and the hash it showed (the exchange's
     * [CoSignExchange.scan]), and appended in turn; with no scan begun there
     * is nothing to bind it to, and it is refused.
     */
    private fun onResponseScanned(raw: String) {
        transition(CoSignExchange.Event.ScanEnded(raw))
        appendQueuedResponse()
    }

    /**
     * Appends the oldest queued response, once nothing else is: a co-signed
     * copy still to be placed or still writing becomes the selected media when
     * it ends, so the response waits and is appended to it, keeping its
     * co-signature. The response leaves the queue only with its outcome.
     *
     * The one place an append starts: a response is appended only to the
     * media it was scanned for (and [appendToMedia] checks that media's
     * payload against the hash the witness signed), and an append already
     * running ([CoSignExchange.runningAppend]) is waited on, never run again.
     * Its outcome is taken only while this screen is resumed
     * ([MediaSaveRuns.outcome]), so never after the state was saved: a
     * screen that goes away leaves it to the next instance.
     */
    private fun appendQueuedResponse() {
        val state = exchange
        if (appending || state.pendingCopy != null || state.runningCopy != null) return
        val queued = state.queued.firstOrNull() ?: return
        val started = state.runningAppend
        // Only the Uri: after a recreation the signature data is still reloading,
        // and the append reads the file's own data anyway. An append already
        // started goes on with the media it started on.
        val target = queued.media
        val expectedHash = queued.contentHash
        val refusal = when {
            target == null -> getString(R.string.cosign_select_media_first)
            // Never appended unchecked: the media must still hold what the witness signed.
            expectedHash == null -> getString(R.string.cosign_response_refused, getString(R.string.cosign_error_no_hash))
            started == null && target != state.media ->
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
            transition(CoSignExchange.Event.AppendEnded(null))
            Snackbar.make(rootLayout, text, Snackbar.LENGTH_LONG).show()
            appendQueuedResponse()
            return
        }
        val id = started ?: UUID.randomUUID().toString().also { transition(CoSignExchange.Event.AppendStarted(it)) }
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
            MediaSaveRuns.outcome(run, lifecycle) { outcome ->
                val result: Any = outcome.getOrElse { it }
                MediaSaveRuns.finished(id)
                appending = false
                val copy = (result as? CoSignOutcome.NeedsCopy)?.let {
                    PendingCoSignedCopy(it.staged, response.signerName, response.fingerprint, it.data, target)
                }
                transition(CoSignExchange.Event.AppendEnded(copy))
                when (result) {
                    is CoSignOutcome.Replaced -> if (exchange.media == target) showAppended(result.data, response.signerName)
                    is CoSignOutcome.NeedsCopy -> launchCopyPicker(copy!!)
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
    }

    /**
     * The one place the co-signed copy's picker opens. A failure building its
     * input or launching it goes through the append's error path and leaves
     * nothing pending: the staged copy is deleted (the media it co-signs is
     * untouched) and the next response goes on.
     */
    private fun launchCopyPicker(copy: PendingCoSignedCopy) {
        try {
            coSignedCopyLauncher.launch(SignedCopyDocument.of(contentResolver, copy.source, "cosigned"))
        } catch (e: Exception) {
            transition(CoSignExchange.Event.CopyDropped)
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
     * Media whose payload is not what the witness signed is refused before
     * anything is written: its own content hash, computed as the signer
     * computes it (streamed, as [MediaHasher.hashCanonicalUri] does, so no
     * size cap applies that signing does not; signature metadata left out),
     * must be [expectedHash], and so must the hash its signature data
     * names. Signature data can be kept on other content, so it alone proves
     * nothing. It runs
     * in [MediaSaveRuns], so it holds only the application [context].
     */
    private fun appendToMedia(context: Context, uri: Uri, entry: SignatureEntry, expectedHash: String): CoSignOutcome {
        val contentResolver = context.contentResolver
        // Typed like the media, so the copy is read and written in the same
        // container (EXIF or XMP) loadSignatures read it from.
        val mimeType = contentResolver.getType(uri)
        val suffix = XmpMetadataHelper.stagingSuffix(mimeType)
        // Named for this process: a later one sweeps it if no screen took it.
        val staged = MediaSaveRuns.stage(MediaPublisher.recoveryDirectory(context), suffix)
        var handed = false
        try {
            val input = contentResolver.openInputStream(uri)
                ?: throw IOException("cannot read the selected media")
            input.use { src -> staged.outputStream().use { dst -> src.copyTo(dst) } }

            val existing = XmpMetadataHelper.readSignature(staged.absolutePath)
                ?: throw IllegalStateException(context.getString(R.string.cosign_no_signature_data))
            val payloadHash = MediaHasher.hashStreamed({ staged.inputStream() }, mimeType).canonical
            if (!payloadHash.equals(expectedHash, ignoreCase = true) ||
                !existing.contentHash.equals(expectedHash, ignoreCase = true)
            ) {
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
        val pending = exchange.pendingCopy ?: return
        if (target == null) {
            transition(CoSignExchange.Event.CopyDropped)
            pending.staged.delete()
            appendQueuedResponse()
            return
        }
        val run = RunningCoSignedCopy(UUID.randomUUID().toString(), target, pending)
        transition(CoSignExchange.Event.CopyStarted(run))
        try {
            runCopy(run)
        } catch (e: Exception) {
            transition(CoSignExchange.Event.CopyEnded(written = false))
            copyShown?.cancel()
            showAppendFailed(e)
            appendQueuedResponse()
        }
    }

    /**
     * Run [run], the exchange's running copy, or wait on it when it already
     * runs (this instance restored it after a recreation). It ends by
     * moving what the co-signed media was bound to (the selection, the open
     * scan, queued responses) to the copy and showing its signatures, or by
     * naming the kept bytes. Its outcome is taken only while this screen is
     * resumed ([MediaSaveRuns.outcome]); an instance that goes first leaves
     * the write and its outcome to the next.
     */
    private fun runCopy(run: RunningCoSignedCopy) {
        val resolver = applicationContext.contentResolver
        val app = applicationContext
        val copy = run.copy
        val lost = getString(R.string.cosign_copy_lost)
        val write = MediaSaveRuns.attach(run.id) {
            // Gone once written and closed (a write before process death), or
            // swept with the process that staged it: the copy counts as
            // written only when the document holds it.
            if (!copy.staged.exists()) {
                val known = knownPublicKey(app, copy.fingerprint)
                if (copyInPlace(resolver, run.target, copy) { fingerprint -> known.takeIf { fingerprint == copy.fingerprint } }) return@attach
                throw IOException(lost)
            }
            MediaPublisher.writeCopy(copy.staged) { MediaPublisher.openCreated(resolver, run.target) }
            AuditLogger.logCoSignReceived(copy.data.contentHash, copy.fingerprint)
        }
        copyShown = lifecycleScope.launch {
            // A read of the original that ended later would show its old
            // signatures. Until the copy is installed it stays the running
            // copy, so a recreation meanwhile still selects it.
            mediaLoad?.join()
            // Throws if this instance went away first: the next one waits on the write.
            MediaSaveRuns.outcome(write, lifecycle) { outcome ->
                val failure = outcome.exceptionOrNull()
                MediaSaveRuns.finished(run.id)
                // The copy carries the co-signed media's content (and hash): it takes its place.
                transition(CoSignExchange.Event.CopyEnded(written = failure == null))
                if (failure != null) {
                    showAppendFailed(failure)
                } else if (exchange.media == run.target) {
                    selectedFileText.text = run.target.lastPathSegment ?: run.target.toString()
                    showAppended(copy.data, copy.signerName)
                }
                appendQueuedResponse()
            }
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
        const val STATE_EXCHANGE = "cosign_exchange"
        const val STATE_WITNESS_MODE = "cosign_witness_mode"
        const val STATE_KEY_ID = "cosign_key_id"
    }
}

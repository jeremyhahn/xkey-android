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
import android.content.Intent
import android.graphics.Color
import androidx.core.content.ContextCompat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.format.Formatter
import android.util.Log
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.withResumed
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
import com.automatethethings.xkey.media.SignedCopyDocument
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignerRole
import com.automatethethings.xkey.media.SignerVerification
import com.automatethethings.xkey.media.XmpContainers
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.CircularProgressIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.time.Instant
import java.util.UUID

/**
 * Activity that handles file operations received via the Android Share sheet.
 *
 * Supports four operations on shared files:
 * - **Sign**: Hash the file and create a cryptographic signature using a local key.
 * - **Verify**: Verify embedded or sidecar signatures against known contacts/keys.
 * - **Encrypt**: Encrypt a file for a selected contact using ECIES (FileEncryptor).
 * - **Decrypt**: Decrypt a `.xkeyenc` file using a local key.
 *
 * Files arrive via [Intent.ACTION_SEND] or [Intent.ACTION_SEND_MULTIPLE].
 * All cryptographic and I/O work runs on [Dispatchers.IO] via [lifecycleScope].
 */
class FileOperationActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "FileOperationActivity"

        // Saved state: output waiting for a save picker
        private const val STATE_SIGNATURE_JSON = "pending_signature_json"
        private const val STATE_SIGNED_COPY_SOURCE = "pending_signed_copy_source"
        private const val STATE_SIGNED_COPY_MIME = "pending_signed_copy_mime"
        private const val STATE_SIGNED_COPY_SIGNATURE = "pending_signed_copy_signature"

        // Saved state: a save writing to the destination the user picked
        private const val STATE_RUNNING_ID = "running_save_id"
        private const val STATE_RUNNING_DESTINATION = "running_save_destination"
        private const val STATE_RUNNING_JSON = "running_save_json"
        private const val STATE_RUNNING_SOURCE = "running_save_source"
        private const val STATE_RUNNING_MIME = "running_save_mime"
        private const val STATE_RUNNING_SIGNATURE = "running_save_signature"

        /**
         * Write [save] to its destination: the sidecar JSON, or a signed copy
         * of its source. Static, over the application's resolver, so a write
         * never holds the activity that started it.
         */
        private fun writeSave(resolver: ContentResolver, recovery: File, save: RunningSave) {
            save.signatureJson?.let { json ->
                MediaPublisher.openCreated(resolver, save.destination).use { it.write(json.toByteArray(Charsets.UTF_8)) }
            }
            save.signedCopy?.let { copy ->
                val written = XmpMetadataHelper.writeSignedCopy(
                    open = { resolver.openInputStream(copy.source) ?: throw IOException("Cannot open ${copy.source}") },
                    openOutput = { MediaPublisher.openCreated(resolver, save.destination) },
                    mimeType = copy.mimeType,
                    data = copy.data,
                    workDir = recovery,
                    destination = save.destination.toString()
                )
                if (!written) throw IOException("${copy.source} cannot carry a new embedded signature")
            }
        }

        // UI colors

        /** Operation indices matching RadioGroup child order. */
        private const val OP_SIGN = 0
        private const val OP_VERIFY = 1
        private const val OP_ENCRYPT = 2
        private const val OP_DECRYPT = 3
    }

    // Database DAOs
    private lateinit var keyDao: KeyDao
    private lateinit var contactDao: ContactDao

    // Crypto
    private lateinit var keystoreManager: KeystoreManager

    // Loaded data
    private var signingKeys: List<KeyEntity> = emptyList()
    private var encryptionKeys: List<KeyEntity> = emptyList()
    private var contacts: List<ContactEntity> = emptyList()

    // Received file URIs
    private var fileUris: List<Uri> = emptyList()

    // Current operation selection
    private var selectedOperation: Int = OP_SIGN

    // UI references
    private lateinit var rootLayout: LinearLayout
    private lateinit var fileInfoText: TextView
    private lateinit var operationGroup: RadioGroup
    private lateinit var keySelectorLabel: TextView
    private lateinit var keySpinner: Spinner
    private lateinit var recipientSelectorLabel: TextView
    private lateinit var recipientSpinner: Spinner
    private lateinit var processButton: MaterialButton
    private lateinit var progressIndicator: CircularProgressIndicator
    private lateinit var resultText: TextView
    private lateinit var resultCard: MaterialCardView

    // Activity result launchers. Every save picker's result goes through
    // onSavePicked, so a cancel always drops its pending output and frees
    // the screen.
    private val createSignatureFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri -> onSavePicked(uri, { pendingSignatureJson = null }, ::saveSignatureToUri) }

    private val createEncryptedFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri -> onSavePicked(uri, pendingEncryptedSave::cancel, ::saveEncryptedToUri) }

    private val createDecryptedFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri -> onSavePicked(uri, pendingDecryptedSave::cancel, ::saveDecryptedToUri) }

    private val pickSidecarLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { verifySidecarSignature(it) } }

    // Typed per launch: the copy is created as the source's own type and suffix.
    private val createSignedCopyLauncher = registerForActivityResult(
        SignedCopyDocument.Create()
    ) { uri -> onSavePicked(uri, { pendingSignedCopy = null }, ::saveSignedCopyToUri) }

    /**
     * A save picker's result: a destination goes to [save]; null is a cancel,
     * which runs [clear] to drop the output waiting for it and ends the
     * operation, so the screen is not left busy.
     */
    private fun onSavePicked(uri: Uri?, clear: () -> Unit, save: (Uri) -> Unit) {
        if (uri != null) {
            save(uri)
        } else {
            clear()
            showProgress(false)
        }
    }

    /** A signed copy of [source], of [mimeType], waiting for the document the user picks. */
    private class PendingSignedCopy(
        val source: Uri,
        val mimeType: String,
        val data: ContentAuthenticityData
    )

    /**
     * A save whose destination the user picked, writing now: the sidecar
     * JSON or a signed copy. It is a separate state from a pending picker.
     * Its write runs in [MediaSaveRuns], not in an instance's scope, and the save
     * is kept in the saved state, so the instance after a recreation waits
     * on the same write (after process death it writes again, to the same
     * destination) and frees the screen when it ends.
     */
    private class RunningSave(
        val id: String,
        val destination: Uri,
        val signatureJson: String?,
        val signedCopy: PendingSignedCopy?
    )

    // Picker pending: the sidecar JSON or a signed copy, waiting for a save location
    private var pendingSignatureJson: String? = null
    private var pendingSignedCopy: PendingSignedCopy? = null

    // Save running: the destination was picked and its write has not ended
    private var runningSave: RunningSave? = null

    // Staging files for sign, encrypt and decrypt (see FileOperationStaging)
    private lateinit var staging: FileOperationStaging
    private lateinit var pendingEncryptedSave: PendingStagedSave
    private lateinit var pendingDecryptedSave: PendingStagedSave

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // This instance's staging session; onDestroy shuts it down
        staging = FileOperationStaging(cacheDir)
        pendingEncryptedSave = PendingStagedSave(staging)
        pendingDecryptedSave = PendingStagedSave(staging)

        // Initialize database and crypto
        val db = XKeyDatabase.getInstance(this)
        keyDao = db.keyDao()
        contactDao = db.contactDao()
        keystoreManager = KeystoreManager(this)

        // A save picker may outlive this instance: its pending output comes back
        restorePendingSaves(savedInstanceState)

        // Extract file URIs from intent
        fileUris = extractFileUris(intent)
        if (fileUris.isEmpty()) {
            Log.w(TAG, "No file URIs received")
            finish()
            return
        }

        // Only a valid share sweeps: it removes what a dead process or a
        // shut-down instance left, never a live instance's staged output
        staging.sweep()

        // Build and set the programmatic UI
        setContentView(buildUI())

        // A restored save is still this screen's operation: Process stays
        // disabled until its picker returns and its write ends (showResult)
        // or the picker is cancelled (onSavePicked). A save that was writing
        // is waited on again; it frees the screen when it ends.
        if (pendingSignatureJson != null || pendingSignedCopy != null) showProgress(true)
        runningSave?.let { runSave(it) }

        // Populate file info
        populateFileInfo()

        // Load keys and contacts
        loadKeysAndContacts()
    }

    /**
     * Keep the saves this screen has open, as two separate states: what an
     * open save picker writes when it returns (the sidecar JSON, the signed
     * copy's source, type and signature), and a save already writing to the
     * destination the user picked. A configuration change or process death
     * then neither loses the signature nor mistakes a running write for a
     * picker still open. Staged files are this instance's and are dropped
     * with it (onDestroy).
     */
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingSignatureJson?.let { outState.putString(STATE_SIGNATURE_JSON, it) }
        pendingSignedCopy?.let {
            outState.putString(STATE_SIGNED_COPY_SOURCE, it.source.toString())
            outState.putString(STATE_SIGNED_COPY_MIME, it.mimeType)
            outState.putString(STATE_SIGNED_COPY_SIGNATURE, it.data.toJsonString())
        }
        runningSave?.let { save ->
            outState.putString(STATE_RUNNING_ID, save.id)
            outState.putString(STATE_RUNNING_DESTINATION, save.destination.toString())
            save.signatureJson?.let { outState.putString(STATE_RUNNING_JSON, it) }
            save.signedCopy?.let {
                outState.putString(STATE_RUNNING_SOURCE, it.source.toString())
                outState.putString(STATE_RUNNING_MIME, it.mimeType)
                outState.putString(STATE_RUNNING_SIGNATURE, it.data.toJsonString())
            }
        }
    }

    private fun restorePendingSaves(state: Bundle?) {
        if (state == null) return
        pendingSignatureJson = state.getString(STATE_SIGNATURE_JSON)
        pendingSignedCopy = restoreSignedCopy(state, STATE_SIGNED_COPY_SOURCE, STATE_SIGNED_COPY_MIME, STATE_SIGNED_COPY_SIGNATURE)
        val id = state.getString(STATE_RUNNING_ID) ?: return
        val destination = state.getString(STATE_RUNNING_DESTINATION) ?: return
        val json = state.getString(STATE_RUNNING_JSON)
        val copy = restoreSignedCopy(state, STATE_RUNNING_SOURCE, STATE_RUNNING_MIME, STATE_RUNNING_SIGNATURE)
        if (json != null || copy != null) runningSave = RunningSave(id, Uri.parse(destination), json, copy)
    }

    private fun restoreSignedCopy(state: Bundle, sourceKey: String, mimeKey: String, signatureKey: String): PendingSignedCopy? {
        val source = state.getString(sourceKey) ?: return null
        val mimeType = state.getString(mimeKey) ?: return null
        val signature = state.getString(signatureKey) ?: return null
        return try {
            PendingSignedCopy(Uri.parse(source), mimeType, ContentAuthenticityData.fromJsonString(signature))
        } catch (e: Exception) {
            Log.w(TAG, "Dropping an unreadable signed copy", e)
            null
        }
    }

    override fun onDestroy() {
        // Every teardown (finish or recreation) drops this instance's staged
        // files and fences its writers: a worker still blocked in its input
        // deletes its file when it returns
        pendingEncryptedSave.take()
        pendingDecryptedSave.take()
        staging.shutdown()
        // Gone for good, not recreated: no instance takes the save's outcome,
        // so it is forgotten once its write ends (which keeps its own bytes
        // on a failure, MediaPublisher).
        if (isFinishing && !isChangingConfigurations) runningSave?.let { MediaSaveRuns.abandon<Unit>(it.id) }
        super.onDestroy()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // -------------------------------------------------------------------------
    // Intent Parsing
    // -------------------------------------------------------------------------

    /**
     * Extract file URIs from the incoming share intent.
     *
     * Handles both [Intent.ACTION_SEND] (single file) and
     * [Intent.ACTION_SEND_MULTIPLE] (multiple files).
     *
     * @param intent The received intent.
     * @return List of content URIs, or empty if none found.
     */
    private fun extractFileUris(intent: Intent): List<Uri> {
        return when (intent.action) {
            Intent.ACTION_SEND -> {
                @Suppress("DEPRECATION")
                val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                if (uri != null) listOf(uri) else emptyList()
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) ?: emptyList()
            }
            else -> emptyList()
        }
    }

    // -------------------------------------------------------------------------
    // Programmatic UI Construction
    // -------------------------------------------------------------------------

    /**
     * Build the complete Material 3 UI programmatically.
     *
     * Layout hierarchy:
     * - LinearLayout root (vertical)
     *   - Toolbar
     *   - NestedScrollView
     *     - LinearLayout content
     *       - File info card
     *       - Operation selector card
     *       - Key selector card
     *       - Recipient selector card
     *       - Process button + progress
     *       - Result card
     *
     * @return The root view to set as content.
     */
    private fun buildUI(): View {
        val dp = { value: Int -> UIHelpers.dpToPxInt(this, value) }

        // Root vertical layout
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurface
            ))
        }

        // Toolbar
        val toolbar = Toolbar(this).apply {
            title = getString(R.string.file_operation_title)
            setTitleTextColor(ContextCompat.getColor(this@FileOperationActivity, R.color.on_primary))
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(ContextCompat.getColor(this@FileOperationActivity, R.color.primary), ContextCompat.getColor(this@FileOperationActivity, R.color.tertiary))
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@FileOperationActivity)
            )
        }
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this@FileOperationActivity, R.color.on_primary))
        rootLayout.addView(toolbar)

        // Scrollable content
        val scrollView = NestedScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1f
            )
        }

        val contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // 1. File info card
        contentLayout.addView(buildFileInfoCard(dp))

        // 2. Operation selector card
        contentLayout.addView(buildOperationSelectorCard(dp))

        // 3. Key selector card
        contentLayout.addView(buildKeySelectorCard(dp))

        // 4. Recipient selector card
        contentLayout.addView(buildRecipientSelectorCard(dp))

        // 5. Process button + progress indicator
        contentLayout.addView(buildProcessSection(dp))

        // 6. Result card
        contentLayout.addView(buildResultCard(dp))

        scrollView.addView(contentLayout)
        rootLayout.addView(scrollView)

        return rootLayout
    }

    /**
     * Build the file information card showing file name and size.
     */
    private fun buildFileInfoCard(dp: (Int) -> Int): MaterialCardView {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
            radius = dp(12).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurfaceContainerLow
            ))
        }

        fileInfoText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dp(16), dp(16), dp(16), dp(16))
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
        }

        card.addView(fileInfoText)
        return card
    }

    /**
     * Build the operation selector card with a RadioGroup.
     */
    private fun buildOperationSelectorCard(dp: (Int) -> Int): MaterialCardView {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
            radius = dp(12).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurfaceContainerLow
            ))
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val sectionTitle = TextView(this).apply {
            text = "Operation"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(ContextCompat.getColor(this@FileOperationActivity, R.color.primary))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(8)
            }
        }
        cardContent.addView(sectionTitle)

        operationGroup = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val operations = listOf(
            getString(R.string.file_operation_sign),
            getString(R.string.file_operation_verify),
            getString(R.string.file_operation_encrypt),
            getString(R.string.file_operation_decrypt)
        )

        operations.forEachIndexed { index, label ->
            val radioButton = RadioButton(this).apply {
                text = label
                id = View.generateViewId()
                layoutParams = RadioGroup.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f
                )
                textSize = 13f
                if (index == OP_SIGN) isChecked = true
            }
            operationGroup.addView(radioButton)
        }

        operationGroup.setOnCheckedChangeListener { group, checkedId ->
            val index = group.indexOfChild(group.findViewById(checkedId))
            selectedOperation = index
            onOperationChanged()
        }

        cardContent.addView(operationGroup)
        card.addView(cardContent)
        return card
    }

    /**
     * Build the key selector card with a Spinner.
     */
    private fun buildKeySelectorCard(dp: (Int) -> Int): MaterialCardView {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
            radius = dp(12).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurfaceContainerLow
            ))
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        keySelectorLabel = TextView(this).apply {
            text = getString(R.string.file_operation_select_key)
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(ContextCompat.getColor(this@FileOperationActivity, R.color.primary))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(8)
            }
        }
        cardContent.addView(keySelectorLabel)

        keySpinner = Spinner(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        cardContent.addView(keySpinner)

        card.addView(cardContent)
        return card
    }

    /**
     * Build the recipient selector card with a Spinner (visible only for Encrypt).
     */
    private fun buildRecipientSelectorCard(dp: (Int) -> Int): MaterialCardView {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
            radius = dp(12).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurfaceContainerLow
            ))
            visibility = View.GONE
            tag = "recipientCard"
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        recipientSelectorLabel = TextView(this).apply {
            text = getString(R.string.file_operation_select_recipient)
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(ContextCompat.getColor(this@FileOperationActivity, R.color.primary))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(8)
            }
        }
        cardContent.addView(recipientSelectorLabel)

        recipientSpinner = Spinner(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        cardContent.addView(recipientSpinner)

        card.addView(cardContent)
        return card
    }

    /**
     * Build the process button and progress indicator section.
     */
    private fun buildProcessSection(dp: (Int) -> Int): LinearLayout {
        val section = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
        }

        processButton = MaterialButton(this).apply {
            text = getString(R.string.file_operation_process)
            setBackgroundColor(ContextCompat.getColor(this@FileOperationActivity, R.color.secondary))
            setTextColor(ContextCompat.getColor(this@FileOperationActivity, R.color.primary))
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            ).apply {
                marginEnd = dp(12)
            }
            setOnClickListener { onProcessClicked() }
        }
        section.addView(processButton)

        progressIndicator = CircularProgressIndicator(this).apply {
            isIndeterminate = true
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                dp(36),
                dp(36)
            )
            indicatorSize = dp(36)
            trackThickness = dp(3)
            setIndicatorColor(ContextCompat.getColor(this@FileOperationActivity, R.color.tertiary))
        }
        section.addView(progressIndicator)

        return section
    }

    /**
     * Build the result card for showing operation outcomes.
     */
    private fun buildResultCard(dp: (Int) -> Int): MaterialCardView {
        resultCard = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            radius = dp(12).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(UIHelpers.resolveThemeColor(
                this@FileOperationActivity,
                com.google.android.material.R.attr.colorSurfaceContainerLow
            ))
            visibility = View.GONE
        }

        resultText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dp(16), dp(16), dp(16), dp(16))
            textSize = 14f
        }

        resultCard.addView(resultText)
        return resultCard
    }

    // -------------------------------------------------------------------------
    // File Info
    // -------------------------------------------------------------------------

    /**
     * Populate the file info card with names and sizes of shared files.
     */
    private fun populateFileInfo() {
        val infoLines = fileUris.map { uri ->
            val name = getFileName(uri) ?: "Unknown file"
            val size = getFileSize(uri)
            val sizeStr = Formatter.formatFileSize(this, size)
            getString(R.string.file_operation_file_info, name, sizeStr)
        }
        fileInfoText.text = infoLines.joinToString("\n")
    }

    /**
     * Query the display name for a content URI.
     *
     * @param uri The content URI to query.
     * @return The display name, or null if unavailable.
     */
    private fun getFileName(uri: Uri): String? {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex >= 0) {
                    return cursor.getString(nameIndex)
                }
            }
        }
        return uri.lastPathSegment
    }

    /**
     * Query the file size for a content URI.
     *
     * @param uri The content URI to query.
     * @return The file size in bytes, or 0 if unavailable.
     */
    private fun getFileSize(uri: Uri): Long {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) {
                    return cursor.getLong(sizeIndex)
                }
            }
        }
        return 0L
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    /**
     * Load keys and contacts from the database, then populate spinners.
     */
    private fun loadKeysAndContacts() {
        lifecycleScope.launch(Dispatchers.IO) {
            val allKeys = keyDao.getAll()
            // Signing-type keys: signing, fido2, ca, or any key with signing algorithm
            signingKeys = allKeys.filter { key ->
                key.keyType in listOf("signing", "fido2", "ca", "attestation") ||
                    key.algorithm.startsWith("ES") ||
                    key.algorithm.startsWith("RS") ||
                    key.algorithm == "Ed25519"
            }
            // Encryption-type keys: encryption keys or EC keys that can do ECDH
            encryptionKeys = allKeys.filter { key ->
                key.keyType == "encryption" ||
                    (key.algorithm.startsWith("ES") && key.keyType != "fido2")
            }
            contacts = contactDao.getAll()

            withContext(Dispatchers.Main) {
                populateKeySpinner()
                populateRecipientSpinner()
                onOperationChanged()
            }
        }
    }

    /**
     * Populate the key spinner with available keys based on the current operation.
     */
    private fun populateKeySpinner() {
        val keys = when (selectedOperation) {
            OP_SIGN -> signingKeys
            OP_DECRYPT -> encryptionKeys
            else -> signingKeys
        }

        if (keys.isEmpty()) {
            keySpinner.adapter = ArrayAdapter(
                this,
                android.R.layout.simple_spinner_item,
                listOf(getString(R.string.file_operation_no_keys))
            ).apply {
                setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            }
            return
        }

        val labels = keys.map { "${it.label} (${it.algorithm})" }
        keySpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            labels
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
    }

    /**
     * Populate the recipient spinner with available contacts.
     */
    private fun populateRecipientSpinner() {
        if (contacts.isEmpty()) {
            recipientSpinner.adapter = ArrayAdapter(
                this,
                android.R.layout.simple_spinner_item,
                listOf(getString(R.string.file_operation_no_contacts))
            ).apply {
                setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            }
            return
        }

        val labels = contacts.map { "${it.name} (${it.algorithm})" }
        recipientSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            labels
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
    }

    // -------------------------------------------------------------------------
    // Operation Change Handling
    // -------------------------------------------------------------------------

    /**
     * Update UI visibility based on the selected operation.
     *
     * - Sign/Decrypt: show key selector, hide recipient selector
     * - Verify: hide both selectors
     * - Encrypt: show recipient selector, hide key selector
     */
    private fun onOperationChanged() {
        val recipientCard = rootLayout.findViewWithTag<View>("recipientCard")

        when (selectedOperation) {
            OP_SIGN -> {
                keySelectorLabel.text = getString(R.string.file_operation_select_key)
                (keySpinner.parent?.parent as? View)?.visibility = View.VISIBLE
                recipientCard?.visibility = View.GONE
                populateKeySpinner()
            }
            OP_VERIFY -> {
                (keySpinner.parent?.parent as? View)?.visibility = View.GONE
                recipientCard?.visibility = View.GONE
            }
            OP_ENCRYPT -> {
                (keySpinner.parent?.parent as? View)?.visibility = View.GONE
                recipientCard?.visibility = View.VISIBLE
            }
            OP_DECRYPT -> {
                keySelectorLabel.text = getString(R.string.file_operation_select_key)
                (keySpinner.parent?.parent as? View)?.visibility = View.VISIBLE
                recipientCard?.visibility = View.GONE
                populateKeySpinner()
            }
        }

        // Hide result card when switching operations
        resultCard.visibility = View.GONE
    }

    // -------------------------------------------------------------------------
    // Process Button
    // -------------------------------------------------------------------------

    /**
     * Handle the process button click by dispatching to the appropriate operation.
     */
    private fun onProcessClicked() {
        showProgress(true)
        resultCard.visibility = View.GONE

        when (selectedOperation) {
            OP_SIGN -> performSign()
            OP_VERIFY -> performVerify()
            OP_ENCRYPT -> performEncrypt()
            OP_DECRYPT -> performDecrypt()
        }
    }

    /**
     * Toggle the progress indicator and button enabled state.
     */
    private fun showProgress(show: Boolean) {
        processButton.isEnabled = !show
        processButton.text = if (show) {
            getString(R.string.file_operation_processing)
        } else {
            getString(R.string.file_operation_process)
        }
        progressIndicator.visibility = if (show) View.VISIBLE else View.GONE
    }

    /**
     * Show a result message in the result card.
     *
     * @param message The result text to display.
     * @param isError Whether this is an error result (affects text color).
     */
    private fun showResult(message: String, isError: Boolean = false) {
        resultText.text = message
        resultText.setTextColor(if (isError) ContextCompat.getColor(this@FileOperationActivity, R.color.security_danger) else ContextCompat.getColor(this@FileOperationActivity, R.color.security_verified))
        resultCard.visibility = View.VISIBLE
        showProgress(false)
    }

    /**
     * Show an error result from an exception.
     *
     * @param e The exception that occurred.
     */
    private fun showError(e: Exception) {
        val message = getString(R.string.file_operation_error, e.message ?: "Unknown error")
        showResult(message, isError = true)
        Log.e(TAG, "File operation failed", e)
    }

    // -------------------------------------------------------------------------
    // Sign Operation
    // -------------------------------------------------------------------------

    /**
     * Sign the first shared file.
     *
     * Flow:
     * 1. Copy file to a temp path (needed for EXIF embedding on images).
     * 2. Hash the file via [MediaHasher.hashUri].
     * 3. Sign the hash bytes using [KeystoreManager.signWithAlgorithm].
     * 4. Build [ContentAuthenticityData] with the signature.
     * 5. If JPEG: embed via [XmpMetadataHelper.writeSignature].
     *    Otherwise: prompt user to save a `.xkeysig` sidecar file.
     * 6. Log the operation via [AuditLogger].
     */
    private fun performSign() {
        if (signingKeys.isEmpty()) {
            showResult(getString(R.string.file_operation_no_keys), isError = true)
            return
        }

        val selectedKeyIndex = keySpinner.selectedItemPosition
        if (selectedKeyIndex < 0 || selectedKeyIndex >= signingKeys.size) {
            showResult(getString(R.string.file_operation_no_keys), isError = true)
            return
        }

        val key = signingKeys[selectedKeyIndex]
        val uri = fileUris.first()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Hash the file content
                val hashHex = MediaHasher.hashCanonicalUri(contentResolver, uri)
                val hashBytes = hexToBytes(hashHex)

                // Sign the hash
                val signatureBytes = keystoreManager.signWithAlgorithm(
                    key.keyId,
                    hashBytes,
                    key.algorithm
                )

                val signatureBase64 = android.util.Base64.encodeToString(
                    signatureBytes, android.util.Base64.NO_WRAP
                )

                // Build ContentAuthenticityData
                val publicKeyDer = key.publicKeyDer
                val fingerprint = if (publicKeyDer != null) {
                    MediaHasher.hashBytes(publicKeyDer)
                } else {
                    key.keyId
                }

                val signatureEntry = SignatureEntry(
                    keyFingerprint = fingerprint,
                    signerName = key.label,
                    algorithm = key.algorithm,
                    value = signatureBase64,
                    timestamp = Instant.now().toString(),
                    role = SignerRole.CREATOR
                )

                val cad = ContentAuthenticityData(
                    contentHash = hashHex,
                    signatures = listOf(signatureEntry)
                )

                // Determine if we can embed in EXIF or need sidecar
                val mimeType = contentResolver.getType(uri) ?: ""
                val fileName = getFileName(uri) ?: "file"

                val jpeg = MediaHasher.isCanonicalisedJpeg(mimeType)
                if (jpeg || sharedSigning(uri, mimeType) == XmpMetadataHelper.SharedSigning.SIGNED_COPY) {
                    // An embedded signature: EXIF for a JPEG, XMP replacing the
                    // one a PNG, WebP or video carries (readers prefer it to a
                    // sidecar). The shared original is never truncated: a file
                    // is replaced atomically (MediaPublisher), any other
                    // provider gets a signed copy at a document the user picks.
                    val path = MediaPublisher.replaceableFile(uri)?.path
                    if (path != null) {
                        XmpMetadataHelper.writeSignature(path, cad)
                        keyDao.recordUsage(key.keyId)
                        AuditLogger.logFileSigned(key.keyId, key.label, fileName)

                        withContext(Dispatchers.Main) {
                            showResult(getString(R.string.file_operation_sign_success))
                        }
                    } else {
                        keyDao.recordUsage(key.keyId)
                        AuditLogger.logFileSigned(key.keyId, key.label, fileName)

                        openSavePicker(
                            pend = { pendingSignedCopy = PendingSignedCopy(uri, mimeType, cad) },
                            clear = { pendingSignedCopy = null }
                        ) {
                            createSignedCopyLauncher.launch(SignedCopyDocument.named(fileName, mimeType.ifBlank { null }, "signed"))
                        }
                    }
                } else {
                    // Save as sidecar: prompt user for output location
                    keyDao.recordUsage(key.keyId)
                    AuditLogger.logFileSigned(key.keyId, key.label, fileName)

                    val json = cad.toJsonString()
                    openSavePicker(
                        pend = { pendingSignatureJson = json },
                        clear = { pendingSignatureJson = null }
                    ) {
                        createSignatureFileLauncher.launch("$fileName.xkeysig")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    /**
     * Hand an output to its save picker: [pend] sets the pending state and
     * [launch] opens the picker together, on the main thread while the screen
     * is resumed, so no recreation falls between them (the saved state never
     * holds a pending save whose picker was not opened). A launch that throws
     * runs [clear]; a screen destroyed first cancels the handoff, leaving
     * nothing pending.
     */
    private suspend fun openSavePicker(pend: () -> Unit, clear: () -> Unit, launch: () -> Unit) {
        withResumed {
            pend()
            try {
                launch()
            } catch (e: RuntimeException) {
                clear()
                throw e
            }
        }
    }

    /**
     * How the shared media at [uri] is signed, reading it only, so media
     * shared with read access alone keeps the sidecar path.
     */
    private fun sharedSigning(uri: Uri, mimeType: String): XmpMetadataHelper.SharedSigning =
        XmpMetadataHelper.sharedSigning(
            open = { contentResolver.openInputStream(uri) ?: throw IOException("Cannot open $uri") },
            format = XmpContainers.formatOf(mimeType)
        )

    /**
     * Write the pending signed copy to the user-selected URI. The shared
     * original is only read; if the write fails, the complete signed copy
     * is kept for recovery and the error names it (MediaPublisher).
     */
    private fun saveSignedCopyToUri(outputUri: Uri) {
        val pending = pendingSignedCopy ?: return showProgress(false)
        pendingSignedCopy = null
        runSave(RunningSave(UUID.randomUUID().toString(), outputUri, null, pending))
    }

    /**
     * Save the pending signature JSON to the user-selected URI.
     */
    private fun saveSignatureToUri(outputUri: Uri) {
        val json = pendingSignatureJson ?: return showProgress(false)
        pendingSignatureJson = null
        runSave(RunningSave(UUID.randomUUID().toString(), outputUri, json, null))
    }

    /**
     * Run [save], or wait on it when it already runs (this instance restored
     * it after a recreation), with the screen busy until it ends. The picker
     * state was cleared when the save started, so a recreation meanwhile
     * restores it as running, never as a picker still open. Whether it
     * succeeds or fails, its end frees the screen; an instance that goes
     * first leaves the write to the next.
     */
    private fun runSave(save: RunningSave) {
        runningSave = save
        showProgress(true)
        val resolver = applicationContext.contentResolver
        val recovery = MediaPublisher.recoveryDirectory(applicationContext)
        val run = MediaSaveRuns.attach(save.id) { writeSave(resolver, recovery, save) }
        lifecycleScope.launch {
            // Throws if this instance went away first, even after the write
            // ended, and waits while it is not resumed: the next instance, or
            // this one once it is back, waits on the write and shows its end.
            MediaSaveRuns.outcome(run, lifecycle) { outcome ->
                val failure = outcome.exceptionOrNull() as Exception?
                MediaSaveRuns.finished(save.id)
                runningSave = null
                if (failure == null) showResult(getString(R.string.file_operation_sign_success)) else showError(failure)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Verify Operation
    // -------------------------------------------------------------------------

    /**
     * Verify signatures on the first shared file.
     *
     * Flow:
     * 1. Hash the file content.
     * 2. Try reading an embedded signature via [XmpMetadataHelper.readSignatureFromUri].
     * 3. If none found, prompt user to pick a `.xkeysig` sidecar file.
     * 4. For each [SignatureEntry], look up the signer by key fingerprint.
     * 5. Show verification results.
     */
    private fun performVerify() {
        val uri = fileUris.first()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Try reading embedded signature
                val mimeType = contentResolver.getType(uri)
                val embeddedData = XmpMetadataHelper.readSignatureFromUri(
                    contentResolver, uri, mimeType
                )

                if (embeddedData != null) {
                    // The stored content hash must match this file before any
                    // signature over it counts: a copied in-band block covers
                    // another file's content.
                    val hashMatches = MediaHasher.contentHashMatchesUri(
                        contentResolver, uri, embeddedData.contentHash, MediaHasher.SignatureSource.IN_BAND
                    )
                    // On a mismatch the block's own line says why, as the
                    // sidecar path does, so the result fails even with no
                    // signature entries.
                    val result = if (hashMatches) {
                        verifySignatures(embeddedData, hashMatches)
                    } else {
                        listOf("Content hash mismatch" to "failed") + verifySignatures(embeddedData, hashMatches)
                    }

                    val fileName = getFileName(uri)
                    AuditLogger.logFileVerified(
                        fileName = fileName,
                        signerCount = embeddedData.signatures.size,
                        verified = result.all { it.second != "failed" }
                    )

                    withContext(Dispatchers.Main) {
                        showVerificationResult(result)
                    }
                } else {
                    // No embedded signature, prompt user to pick sidecar
                    withContext(Dispatchers.Main) {
                        pickSidecarLauncher.launch(arrayOf("application/json", "*/*"))
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    /**
     * Verify a sidecar signature file selected by the user.
     *
     * @param sidecarUri URI of the `.xkeysig` file.
     */
    private fun verifySidecarSignature(sidecarUri: Uri) {
        val fileUri = fileUris.first()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val sidecarJson = contentResolver.openInputStream(sidecarUri)?.use { input ->
                    input.bufferedReader().readText()
                } ?: throw IllegalStateException("Cannot read sidecar file")

                val cad = ContentAuthenticityData.fromJsonString(sidecarJson)

                // A sidecar may cover the canonical or the whole-file hash.
                val hashMatches = MediaHasher.contentHashMatchesUri(
                    contentResolver, fileUri, cad.contentHash, MediaHasher.SignatureSource.SIDECAR
                )
                val results = if (hashMatches) {
                    verifySignatures(cad, hashMatches)
                } else {
                    listOf("Content hash mismatch" to "failed")
                }

                val fileName = getFileName(fileUri)
                AuditLogger.logFileVerified(
                    fileName = fileName,
                    signerCount = cad.signatures.size,
                    verified = results.all { it.second != "failed" }
                )

                withContext(Dispatchers.Main) {
                    showVerificationResult(results)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    /**
     * Verify each signature entry against known keys and contacts.
     *
     * For each [SignatureEntry] this looks up the contact and the local keys
     * and leaves the decision to [SignerVerification.verify], the rule this
     * screen shares with the verified-media viewer.
     *
     * @param cad The content authenticity data containing signatures.
     * @param contentHashMatches Whether `cad.contentHash` matches the file;
     *        when it does not, every entry fails.
     * @return List of pairs: (signer description, status).
     */
    private suspend fun verifySignatures(
        cad: ContentAuthenticityData,
        contentHashMatches: Boolean
    ): List<Pair<String, String>> {
        return cad.signatures.map { entry ->
            try {
                val contact = contactDao.getByFingerprint(entry.keyFingerprint)
                val localKeys = if (contact == null) {
                    keyDao.getAll().map {
                        SignerVerification.LocalKey(it.keyId, it.label, it.publicKeyDer)
                    }
                } else {
                    emptyList()
                }
                val result = SignerVerification.verify(
                    entry = entry,
                    storedContentHash = cad.contentHash,
                    contentHashMatches = contentHashMatches,
                    contact = contact?.let { SignerVerification.Contact(it.name, it.publicKeyDer) },
                    localKeys = localKeys
                )
                result.displayName to when (result.status) {
                    SignerVerification.Status.VERIFIED -> "verified"
                    SignerVerification.Status.FAILED -> "failed"
                    SignerVerification.Status.UNKNOWN -> "unknown"
                }
            } catch (e: Exception) {
                val signerDesc = entry.signerName ?: entry.keyFingerprint.take(16) + "..."
                signerDesc to "failed"
            }
        }
    }

    /**
     * Display verification results in the result card.
     *
     * @param results List of (signer description, status) pairs.
     */
    private fun showVerificationResult(results: List<Pair<String, String>>) {
        val sb = StringBuilder()
        results.forEach { (signer, status) ->
            val statusLabel = when (status) {
                "verified" -> "Verified"
                "unknown" -> "Unknown signer"
                "failed" -> "Failed"
                else -> status
            }
            sb.appendLine("$signer: $statusLabel")
        }

        val allVerified = results.all { it.second == "verified" }
        val anyFailed = results.any { it.second == "failed" }

        val headerText = when {
            allVerified -> getString(R.string.file_operation_verify_success)
            anyFailed -> getString(R.string.file_operation_verify_failed)
            else -> "Verification complete"
        }

        showResult("$headerText\n\n${sb.toString().trim()}", isError = anyFailed)
    }

    // -------------------------------------------------------------------------
    // Encrypt Operation
    // -------------------------------------------------------------------------

    /**
     * Encrypt the first shared file for a selected recipient contact.
     *
     * Flow:
     * 1. Get the selected contact's public key DER bytes.
     * 2. Create a [FileEncryptor] and encrypt the file stream.
     * 3. Prompt user to save the `.xkeyenc` output via document picker.
     * 4. Log the operation.
     */
    private fun performEncrypt() {
        if (contacts.isEmpty()) {
            showResult(getString(R.string.file_operation_no_contacts), isError = true)
            return
        }

        val selectedIndex = recipientSpinner.selectedItemPosition
        if (selectedIndex < 0 || selectedIndex >= contacts.size) {
            showResult(getString(R.string.file_operation_no_contacts), isError = true)
            return
        }

        val recipient = contacts[selectedIndex]
        val uri = fileUris.first()
        val fileName = getFileName(uri) ?: "file"

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Encrypt to a staging file
                val fileEncryptor = FileEncryptor(keystoreManager)
                stageForSave(
                    staging,
                    "$fileName.xkeyenc",
                    write = { staged ->
                        contentResolver.openInputStream(uri)?.use { input ->
                            FileOutputStream(staged).use { output ->
                                fileEncryptor.encryptForRecipient(
                                    recipient.publicKeyDer,
                                    input,
                                    output
                                )
                            }
                        } ?: throw IllegalStateException("Cannot open input file")
                    },
                    prepare = {
                        AuditLogger.logFileEncrypted(
                            recipientFingerprint = recipient.publicKeyFingerprint,
                            fileName = fileName
                        )
                    },
                    handOff = { tempFile ->
                        withContext(Dispatchers.Main) {
                            // Keep the staging file for the launcher callback
                            pendingEncryptedSave.handOff(tempFile) {
                                createEncryptedFileLauncher.launch("$fileName.xkeyenc")
                            }
                        }
                    }
                )
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    private fun saveEncryptedToUri(outputUri: Uri) {
        val tempFile = pendingEncryptedSave.take() ?: return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                staging.deliverTo(tempFile) { MediaPublisher.openCreated(contentResolver, outputUri) }

                withContext(Dispatchers.Main) {
                    showResult(getString(R.string.file_operation_encrypt_success))
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Decrypt Operation
    // -------------------------------------------------------------------------

    /**
     * Decrypt the first shared `.xkeyenc` file using a selected local key.
     *
     * Flow:
     * 1. Get the selected local key ID.
     * 2. Create a [FileEncryptor] and decrypt the file stream.
     * 3. Prompt user to save the decrypted output via document picker.
     * 4. Log the operation.
     */
    private fun performDecrypt() {
        if (encryptionKeys.isEmpty()) {
            showResult(getString(R.string.file_operation_no_keys), isError = true)
            return
        }

        val selectedIndex = keySpinner.selectedItemPosition
        if (selectedIndex < 0 || selectedIndex >= encryptionKeys.size) {
            showResult(getString(R.string.file_operation_no_keys), isError = true)
            return
        }

        val key = encryptionKeys[selectedIndex]
        val uri = fileUris.first()
        val originalName = getFileName(uri) ?: "file"
        // Strip .xkeyenc extension for the output name
        val outputName = if (originalName.endsWith(".xkeyenc")) {
            originalName.removeSuffix(".xkeyenc")
        } else {
            "decrypted_$originalName"
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Decrypt to a staging file
                val fileEncryptor = FileEncryptor(keystoreManager)
                stageForSave(
                    staging,
                    outputName,
                    write = { staged ->
                        contentResolver.openInputStream(uri)?.use { input ->
                            FileOutputStream(staged).use { output ->
                                fileEncryptor.decryptWithKey(key.keyId, input, output)
                            }
                        } ?: throw IllegalStateException("Cannot open input file")
                    },
                    prepare = {
                        keyDao.recordUsage(key.keyId)
                        AuditLogger.logFileDecrypted(key.keyId, originalName)
                    },
                    handOff = { tempFile ->
                        withContext(Dispatchers.Main) {
                            pendingDecryptedSave.handOff(tempFile) {
                                createDecryptedFileLauncher.launch(outputName)
                            }
                        }
                    }
                )
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    private fun saveDecryptedToUri(outputUri: Uri) {
        val tempFile = pendingDecryptedSave.take() ?: return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                staging.deliverTo(tempFile) { MediaPublisher.openCreated(contentResolver, outputUri) }

                withContext(Dispatchers.Main) {
                    showResult(getString(R.string.file_operation_decrypt_success))
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError(e) }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /**
     * Convert a hex-encoded string to a byte array.
     *
     * @param hex The hex string (e.g., "aabbcc").
     * @return The decoded byte array.
     */
    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) +
                Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}

/** The staged file one save picker is open for. */
internal class PendingStagedSave(private val staging: FileOperationStaging) {

    @Volatile
    var file: File? = null
        private set

    /**
     * Make [staged] the pending file, releasing the one it replaces, and run
     * [launch] (the picker). When [launch] throws, [staged] is released and
     * nothing is left pending.
     */
    fun handOff(staged: File, launch: () -> Unit) {
        file?.takeIf { it != staged }?.let { staging.release(it) }
        file = staged
        try {
            launch()
        } catch (e: Throwable) {
            if (file == staged) file = null
            staging.release(staged)
            throw e
        }
    }

    /** Take the pending file for the save callback, leaving nothing pending. */
    fun take(): File? = file.also { file = null }

    /** The user cancelled the picker: delete the pending file. */
    fun cancel() {
        take()?.let { staging.release(it) }
    }

    /** A save picker's result: a destination goes to [save]; null is a cancel. */
    fun <T : Any> onResult(result: T?, save: (T) -> Unit) {
        if (result != null) save(result) else cancel()
    }
}

/**
 * Stage [write]'s output, run [prepare] (usage record, audit), then
 * [handOff] it to a save picker. Until the handoff returns the staged file
 * is this call's: when [prepare] or [handOff] throws it is released, so a
 * failed attempt never leaves plaintext behind for the session's lifetime.
 */
internal suspend fun stageForSave(
    staging: FileOperationStaging,
    displayName: String?,
    write: suspend (File) -> Unit,
    prepare: suspend () -> Unit,
    handOff: suspend (File) -> Unit
) {
    val file = staging.stage(displayName) { write(it) }
    try {
        prepare()
        handOff(file)
    } catch (e: Throwable) {
        staging.release(file)
        throw e
    }
}

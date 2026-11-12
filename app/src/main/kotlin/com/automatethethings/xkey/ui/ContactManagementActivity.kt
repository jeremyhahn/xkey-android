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

import android.Manifest
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.ContactKeyParser
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.qr.QrCodeScannerHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for managing recipient public key contacts.
 *
 * Provides a professional Material 3 UI for importing, viewing, and managing
 * public keys belonging to contacts/recipients. These keys are used for file
 * encryption and signature verification operations.
 *
 * Features:
 * - Hero summary card with contact count
 * - RecyclerView with DiffUtil for efficient list updates
 * - FAB with bottom sheet for import options (File, QR, Paste)
 * - Toolbar action for exporting own public key as QR
 * - Detail dialog with fingerprint, algorithm, source, and delete action
 * - Support for EC (ES256) and RSA (RS256) public key parsing
 */
class ContactManagementActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /** Menu item ID for exporting own public key as QR. */
        private const val MENU_EXPORT_QR = 1

        /** Animation duration for FAB show/hide. */
        private const val FAB_ANIMATION_DURATION = 250L

        /** Value recorded in [ContactEntity.source] for QR-scanned contacts. */
        private const val SOURCE_QR = "qr"

        /** Discriminator carried by the xKey contact QR envelope. */
        private const val QR_PAYLOAD_TYPE = "xkey-contact"

        /** Envelope version emitted by this build. */
        private const val QR_PAYLOAD_VERSION = 1

        /** Edge length of the rendered public key QR bitmap, in dp. */
        private const val QR_EXPORT_SIZE_DP = 240

        /** Height of the camera preview inside the scan dialog, in dp. */
        private const val QR_PREVIEW_HEIGHT_DP = 280
    }

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private val contactDao by lazy { XKeyDatabase.getInstance(this).contactDao() }

    private val keyDao by lazy { XKeyDatabase.getInstance(this).keyDao() }

    private val keystoreManager by lazy { KeystoreManager(this) }

    // -------------------------------------------------------------------------
    // UI Components
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var fab: ExtendedFloatingActionButton
    private lateinit var adapter: ContactListAdapter

    // Summary card views
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView

    // All contacts list
    private var allContacts: List<ContactEntity> = emptyList()

    // FAB visibility tracking
    private var isFabVisible = true

    // Date formatter
    private val dateFormat = SimpleDateFormat("MMM dd, yyyy", Locale.getDefault())

    // -------------------------------------------------------------------------
    // Activity Result Launchers
    // -------------------------------------------------------------------------

    private val openDocumentLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri ?: return@registerForActivityResult
        lifecycleScope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.use { it.readBytes() }
                }
                if (bytes == null) {
                    showError("Failed to read file")
                    return@launch
                }
                importPublicKeyBytes(bytes, "file")
            } catch (e: Exception) {
                showError(e.message ?: "Unknown error")
            }
        }
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            showQrScanDialog()
        } else {
            Snackbar.make(
                rootLayout,
                R.string.contact_qr_camera_denied,
                Snackbar.LENGTH_LONG
            ).show()
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUI()
        setContentView(rootLayout)
        observeContacts()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(Menu.NONE, MENU_EXPORT_QR, 0, R.string.contact_export_qr)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressedDispatcher.onBackPressed()
                true
            }
            MENU_EXPORT_QR -> {
                showExportQrDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // -------------------------------------------------------------------------
    // UI Construction
    // -------------------------------------------------------------------------

    /**
     * Builds the complete UI programmatically.
     */
    private fun buildUI() {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                android.R.attr.colorBackground
            ))
        }

        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        buildToolbar()
        buildSummaryHeroCard()
        buildContactList()
        buildEmptyState()
        buildFab()

        rootLayout.addView(contentLayout)
        rootLayout.addView(fab)
    }

    /**
     * Creates the toolbar with gradient background and back navigation.
     */
    private fun buildToolbar() {
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val gradientStart = ContextCompat.getColor(this, R.color.gradient_primary_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_primary_end)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(gradientStart, gradientEnd)
        )
        toolbarContainer.background = gradient

        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@ContactManagementActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.contact_management_title)
            setTitleTextColor(ContextCompat.getColor(
                this@ContactManagementActivity,
                R.color.on_primary
            ))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.contact_management_subtitle)
            setTextColor(ContextCompat.getColor(
                this@ContactManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 12)
            )
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(subtitle)
        contentLayout.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_chevron_right)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    /**
     * Creates the hero summary card with contact count.
     */
    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@ContactManagementActivity, 100)
        }

        val gradientStart = ContextCompat.getColor(this, R.color.gradient_security_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_security_end)
        PremiumCardFactory.applyDiagonalGradient(summaryCard, gradientStart, gradientEnd)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 20),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 20),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 20),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 20)
            )
        }

        // Left section: Icon and count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        val contactIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_modern)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@ContactManagementActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 64),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
            }
        }

        val textSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        totalCountText = TextView(this).apply {
            text = "0"
            textSize = 48f
            setTextColor(ContextCompat.getColor(
                this@ContactManagementActivity,
                R.color.on_primary
            ))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.contact_summary_none)
            textSize = 14f
            setTextColor(ContextCompat.getColor(
                this@ContactManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(contactIcon)
        countSection.addView(textSection)

        cardContent.addView(countSection)
        summaryCard.addView(cardContent)
        contentLayout.addView(summaryCard)
    }

    /**
     * Creates the RecyclerView for displaying the contact list.
     */
    private fun buildContactList() {
        adapter = ContactListAdapter()

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@ContactManagementActivity)
            this.adapter = this@ContactManagementActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 12),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 4),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 12),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 88)
            )
            clipToPadding = false

            addOnScrollListener(object : RecyclerView.OnScrollListener() {
                override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                    if (dy > 0 && isFabVisible) {
                        hideFab()
                    } else if (dy < 0 && !isFabVisible) {
                        showFab()
                    }
                }
            })
        }

        recyclerView.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator().apply {
            addDuration = 200
            removeDuration = 200
            moveDuration = 200
            changeDuration = 200
        }

        contentLayout.addView(recyclerView)
    }

    /**
     * Creates the empty state view with icon and description.
     */
    private fun buildEmptyState() {
        emptyStateContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 48),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 48),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 48),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_modern)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@ContactManagementActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 96),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.contact_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.contact_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 32)
            }
        }

        val importButton = com.google.android.material.button.MaterialButton(this).apply {
            text = getString(R.string.contact_import_file)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { showImportBottomSheet() }
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        emptyStateContainer.addView(importButton)
        contentLayout.addView(emptyStateContainer)
    }

    /**
     * Creates the floating action button for importing contacts.
     */
    private fun buildFab() {
        fab = ExtendedFloatingActionButton(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.BOTTOM or Gravity.END
                setMargins(
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
                )
            }
            text = getString(R.string.contact_import_file)
            setIconResource(android.R.drawable.ic_input_add)
            backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@ContactManagementActivity, R.color.secondary)
            )
            setTextColor(ContextCompat.getColor(
                this@ContactManagementActivity,
                R.color.on_secondary
            ))
            iconTint = ColorStateList.valueOf(
                ContextCompat.getColor(this@ContactManagementActivity, R.color.on_secondary)
            )
            setOnClickListener { showImportBottomSheet() }
        }
    }

    /**
     * Shows the FAB with animation.
     */
    private fun showFab() {
        isFabVisible = true
        fab.extend()
        fab.animate()
            .translationY(0f)
            .alpha(1f)
            .setDuration(FAB_ANIMATION_DURATION)
            .start()
    }

    /**
     * Hides the FAB with animation.
     */
    private fun hideFab() {
        isFabVisible = false
        fab.shrink()
        fab.animate()
            .translationY(UIHelpers.dpToPx(this, 100f))
            .alpha(0f)
            .setDuration(FAB_ANIMATION_DURATION)
            .start()
    }

    // -------------------------------------------------------------------------
    // Data Management
    // -------------------------------------------------------------------------

    /**
     * Observes all contacts reactively and updates the UI on changes.
     */
    private fun observeContacts() {
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                contactDao.observeAll().collectLatest { contacts ->
                    allContacts = contacts
                    updateContactList()
                    updateSummaryCard()
                }
            }
        }
    }

    /**
     * Updates the RecyclerView and empty state visibility.
     */
    private fun updateContactList() {
        adapter.submitList(allContacts)

        if (allContacts.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyStateContainer.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyStateContainer.visibility = View.GONE
        }
    }

    /**
     * Updates the hero summary card with contact count.
     */
    private fun updateSummaryCard() {
        val count = allContacts.size
        totalCountText.text = count.toString()
        totalLabelText.text = if (count == 0) {
            getString(R.string.contact_summary_none)
        } else {
            resources.getQuantityString(R.plurals.contact_summary_count, count, count)
        }
    }

    // -------------------------------------------------------------------------
    // Import Operations
    // -------------------------------------------------------------------------

    /**
     * Shows the import bottom sheet with File, QR, and Paste options.
     */
    private fun showImportBottomSheet() {
        val bottomSheet = BottomSheetDialog(this)

        val sheetLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24)
            )
        }

        // Title
        val title = TextView(this).apply {
            text = getString(R.string.contact_management_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
            }
        }
        sheetLayout.addView(title)

        // Import from File option
        sheetLayout.addView(createImportOption(
            getString(R.string.contact_import_file),
            android.R.drawable.ic_menu_upload
        ) {
            bottomSheet.dismiss()
            openDocumentLauncher.launch(arrayOf("*/*"))
        })

        // Scan QR Code option
        sheetLayout.addView(createImportOption(
            getString(R.string.contact_import_qr),
            android.R.drawable.ic_menu_camera
        ) {
            bottomSheet.dismiss()
            requestQrScan()
        })

        // Paste Public Key option
        sheetLayout.addView(createImportOption(
            getString(R.string.contact_import_paste),
            android.R.drawable.ic_menu_edit
        ) {
            bottomSheet.dismiss()
            showPasteDialog()
        })

        bottomSheet.setContentView(sheetLayout)
        bottomSheet.show()
    }

    /**
     * Creates an import option row for the bottom sheet.
     */
    private fun createImportOption(
        text: String,
        iconRes: Int,
        onClick: () -> Unit
    ): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 4)
            }
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 12),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 14),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 12),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 14)
            )
            isClickable = true
            isFocusable = true
            background = UIHelpers.createRoundedDrawable(
                android.graphics.Color.TRANSPARENT,
                UIHelpers.dpToPx(this@ContactManagementActivity, 12f)
            )
            setOnClickListener { onClick() }

            // Add ripple on touch
            val typedValue = android.util.TypedValue()
            context.theme.resolveAttribute(
                android.R.attr.selectableItemBackground,
                typedValue,
                true
            )
            foreground = ContextCompat.getDrawable(context, typedValue.resourceId)

            val icon = ImageView(context).apply {
                setImageResource(iconRes)
                imageTintList = ColorStateList.valueOf(
                    UIHelpers.resolveThemeColor(
                        this@ContactManagementActivity,
                        androidx.appcompat.R.attr.colorPrimary
                    )
                )
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                    UIHelpers.dpToPxInt(this@ContactManagementActivity, 24)
                ).apply {
                    marginEnd = UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
                }
            }
            addView(icon)

            val label = TextView(context).apply {
                this.text = text
                textSize = 16f
                setTextColor(UIHelpers.resolveThemeColor(
                    this@ContactManagementActivity,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }
            addView(label)
        }
    }

    /**
     * Ensures the camera permission is held, then opens the QR scan dialog.
     */
    private fun requestQrScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            showQrScanDialog()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    /**
     * Shows a live camera preview and imports the first QR code it decodes.
     *
     * The scan is bound to [ScanLifecycle] rather than the activity so that
     * CameraX releases the camera as soon as the dialog goes away, including
     * when the user cancels.
     */
    private fun showQrScanDialog() {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            )
        }

        val previewView = PreviewView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.dpToPxInt(this@ContactManagementActivity, QR_PREVIEW_HEIGHT_DP)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(
                    this@ContactManagementActivity,
                    com.google.android.material.R.attr.colorSurfaceVariant
                ),
                UIHelpers.dpToPx(this@ContactManagementActivity, 16f)
            )
            clipToOutline = true
        }
        dialogLayout.addView(previewView)

        val instruction = TextView(this).apply {
            text = getString(R.string.contact_qr_scan_instruction)
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
            }
        }
        dialogLayout.addView(instruction)

        val scanLifecycle = ScanLifecycle()
        var resolved = false

        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.contact_import_qr))
            .setView(dialogLayout)
            .setNegativeButton(getString(R.string.button_cancel), null)
            .create()

        val scannerHelper = QrCodeScannerHelper(
            context = this,
            lifecycleOwner = scanLifecycle,
            previewView = previewView,
            onResult = { value ->
                runOnUiThread {
                    if (!resolved) {
                        resolved = true
                        dialog.dismiss()
                        importScannedPayload(value)
                    }
                }
            }
        )

        dialog.setOnDismissListener {
            scannerHelper.stop()
            scanLifecycle.destroy()
            if (!resolved) {
                resolved = true
                Snackbar.make(
                    rootLayout,
                    R.string.contact_qr_scan_cancelled,
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }

        dialog.show()
        scanLifecycle.start()
        scannerHelper.start()
    }

    /**
     * Parses a scanned QR payload and continues into the normal import flow.
     *
     * @param raw The decoded QR text.
     */
    private fun importScannedPayload(raw: String) {
        val payload = raw.trim()
        val envelope = parseContactEnvelope(payload)
        val keyMaterial = envelope?.publicKeyPem ?: payload

        val der = ContactKeyParser.decodePem(keyMaterial)
        if (der == null || ContactKeyParser.parse(der) == null) {
            showError(getString(R.string.contact_qr_invalid))
            return
        }

        importPublicKeyBytes(
            bytes = der,
            source = SOURCE_QR,
            suggestedName = envelope?.label,
            algorithmHint = envelope?.algorithm
        )
    }

    /**
     * Decodes the xKey contact QR envelope.
     *
     * Field names mirror the `local.sharePublicKey` wire parameters so that a
     * contact added by scanning is indistinguishable from one pushed over the
     * pairing channel. Unknown envelope versions are still read rather than
     * rejected: `public_key_pem` is the only field an importer needs.
     *
     * @param text The decoded QR text.
     * @return The envelope contents, or null if [text] is not an xKey contact envelope.
     */
    private fun parseContactEnvelope(text: String): ContactQrEnvelope? {
        if (!text.startsWith("{")) return null
        return try {
            val json = JSONObject(text)
            if (json.optString("type") != QR_PAYLOAD_TYPE) return null
            val pem = json.optString("public_key_pem")
            if (pem.isBlank()) return null
            ContactQrEnvelope(
                label = json.optString("label").ifBlank { null },
                algorithm = json.optString("algorithm").ifBlank { null },
                publicKeyPem = pem
            )
        } catch (_: JSONException) {
            null
        }
    }

    /**
     * Contents of a scanned xKey contact QR envelope.
     */
    private data class ContactQrEnvelope(
        val label: String?,
        val algorithm: String?,
        val publicKeyPem: String
    )

    /**
     * Lifecycle owner scoped to a single QR scan dialog.
     *
     * CameraX keeps the camera bound until the lifecycle it was given reaches
     * DESTROYED, so the dialog needs a lifecycle of its own.
     */
    private class ScanLifecycle : LifecycleOwner {
        private val registry = LifecycleRegistry(this)

        override val lifecycle: Lifecycle get() = registry

        fun start() {
            registry.currentState = Lifecycle.State.RESUMED
        }

        fun destroy() {
            registry.currentState = Lifecycle.State.DESTROYED
        }
    }

    /**
     * Shows a dialog for pasting PEM-encoded public key.
     */
    private fun showPasteDialog() {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            )
        }

        val pemInput = EditText(this).apply {
            hint = getString(R.string.contact_paste_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 4
            maxLines = 10
            gravity = Gravity.TOP or Gravity.START
            typeface = Typeface.MONOSPACE
        }
        dialogLayout.addView(pemInput)

        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.contact_import_paste))
            .setView(dialogLayout)
            .setPositiveButton(getString(R.string.contact_import_paste)) { _, _ ->
                val pem = pemInput.text.toString().trim()
                if (pem.isNotEmpty()) {
                    val bytes = ContactKeyParser.decodePem(pem)
                    if (bytes != null) {
                        importPublicKeyBytes(bytes, "paste")
                    } else {
                        showError("Invalid PEM format")
                    }
                }
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Offers this device's own public keys and renders the chosen one as a QR code.
     */
    private fun showExportQrDialog() {
        lifecycleScope.launch {
            val keys = withContext(Dispatchers.IO) { loadOwnPublicKeys() }

            when {
                keys.isEmpty() -> MaterialAlertDialogBuilder(this@ContactManagementActivity)
                    .setTitle(getString(R.string.contact_export_qr))
                    .setMessage(getString(R.string.contact_export_no_keys))
                    .setPositiveButton(android.R.string.ok, null)
                    .show()

                keys.size == 1 -> showPublicKeyQrDialog(keys.first())

                else -> {
                    val entries = keys.map {
                        getString(R.string.contact_export_key_entry, it.label, it.algorithm)
                    }.toTypedArray()
                    MaterialAlertDialogBuilder(this@ContactManagementActivity)
                        .setTitle(getString(R.string.contact_export_select_key))
                        .setItems(entries) { _, which -> showPublicKeyQrDialog(keys[which]) }
                        .setNegativeButton(getString(R.string.button_cancel), null)
                        .show()
                }
            }
        }
    }

    /**
     * Collects the keys whose public half this device can actually present.
     *
     * A key qualifies only when Android Keystore yields a public key for it,
     * which excludes symmetric keys and keys that merely reference material
     * held by a paired desktop.
     */
    private suspend fun loadOwnPublicKeys(): List<OwnPublicKey> {
        return keyDao.getAll().mapNotNull { key ->
            keystoreManager.getPublicKeyPEM(key.keyId)?.let { pem ->
                OwnPublicKey(
                    keyId = key.keyId,
                    label = key.label,
                    algorithm = key.algorithm,
                    publicKeyPem = pem
                )
            }
        }
    }

    /**
     * Renders [key] as a QR code the peer device can scan into its contacts.
     */
    private fun showPublicKeyQrDialog(key: OwnPublicKey) {
        val payload = JSONObject().apply {
            put("type", QR_PAYLOAD_TYPE)
            put("v", QR_PAYLOAD_VERSION)
            put("label", key.label)
            put("algorithm", key.algorithm)
            put("key_id", key.keyId)
            put("public_key_pem", key.publicKeyPem)
        }.toString()

        val sizePx = UIHelpers.dpToPxInt(this, QR_EXPORT_SIZE_DP)
        val bitmap = try {
            encodeQrBitmap(payload, sizePx)
        } catch (e: Exception) {
            android.util.Log.e("ContactManagement", "QR encoding failed", e)
            showError(getString(R.string.contact_export_qr_failed))
            return
        }

        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            )
        }

        // Scanners need dark modules on a light background, so this surface is
        // deliberately fixed rather than following the app's light/dark theme.
        val qrFrame = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 16)
            }
            background = UIHelpers.createRoundedDrawable(
                android.graphics.Color.WHITE,
                UIHelpers.dpToPx(this@ContactManagementActivity, 16f)
            )
            val inset = UIHelpers.dpToPxInt(this@ContactManagementActivity, 12)
            setPadding(inset, inset, inset, inset)
        }

        qrFrame.addView(ImageView(this).apply {
            setImageBitmap(bitmap)
            layoutParams = FrameLayout.LayoutParams(sizePx, sizePx)
            contentDescription = getString(R.string.contact_export_qr_instruction)
        })
        dialogLayout.addView(qrFrame)

        val instruction = TextView(this).apply {
            text = getString(R.string.contact_export_qr_instruction)
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 12)
            }
        }
        dialogLayout.addView(instruction)

        val algorithmLabel = TextView(this).apply {
            text = getString(R.string.contact_algorithm, key.algorithm)
            textSize = 13f
            gravity = Gravity.CENTER
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 4)
            }
        }
        dialogLayout.addView(algorithmLabel)

        val der = ContactKeyParser.decodePem(key.publicKeyPem)
        if (der != null) {
            dialogLayout.addView(TextView(this).apply {
                text = getString(
                    R.string.contact_fingerprint,
                    formatFingerprint(ContactKeyParser.fingerprint(der))
                )
                textSize = 12f
                typeface = Typeface.MONOSPACE
                gravity = Gravity.CENTER
                setTextColor(UIHelpers.resolveThemeColor(
                    this@ContactManagementActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            })
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(key.label)
            .setView(dialogLayout)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /**
     * Encodes [content] as a square QR bitmap of about [sizePx] pixels per side.
     *
     * ZXing enlarges the symbol past the requested size when the content needs
     * more modules than pixels, so the bitmap is sized from the matrix.
     *
     * @throws com.google.zxing.WriterException if the content does not fit a QR symbol.
     */
    private fun encodeQrBitmap(content: String, sizePx: Int): Bitmap {
        val hints = mapOf<EncodeHintType, Any>(
            EncodeHintType.CHARACTER_SET to Charsets.UTF_8.name()
        )
        val matrix = QRCodeWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            hints
        )

        val width = matrix.width
        val height = matrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                pixels[rowOffset + x] = if (matrix[x, y]) {
                    android.graphics.Color.BLACK
                } else {
                    android.graphics.Color.WHITE
                }
            }
        }

        return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, width, 0, 0, width, height)
        }
    }

    /**
     * A public key held by this device, ready to be encoded into a QR code.
     */
    private data class OwnPublicKey(
        val keyId: String,
        val label: String,
        val algorithm: String,
        val publicKeyPem: String
    )

    // -------------------------------------------------------------------------
    // Public Key Parsing
    // -------------------------------------------------------------------------

    /**
     * Attempts to import public key bytes by parsing and prompting for a name.
     *
     * @param bytes Raw key bytes, either DER or PEM.
     * @param source Value recorded in [ContactEntity.source].
     * @param suggestedName Name to pre-fill in the name prompt, if the payload carried one.
     * @param algorithmHint Algorithm declared by the payload; the one detected from the key wins.
     */
    private fun importPublicKeyBytes(
        bytes: ByteArray,
        source: String,
        suggestedName: String? = null,
        algorithmHint: String? = null
    ) {
        val parsed = ContactKeyParser.parse(bytes)
        if (parsed == null) {
            showError("Unable to parse public key. Supported formats: DER, PEM (EC or RSA).")
            return
        }

        val algorithm = ContactKeyParser.resolveAlgorithm(algorithmHint, parsed.algorithm)
        showNamePromptDialog(parsed.fingerprint, algorithm, parsed.der, source, suggestedName)
    }

    /**
     * Formats a hex fingerprint into colon-separated uppercase pairs.
     */
    private fun formatFingerprint(fingerprint: String): String {
        return fingerprint.uppercase().chunked(2).joinToString(":")
    }

    // -------------------------------------------------------------------------
    // Name Prompt and Insert
    // -------------------------------------------------------------------------

    /**
     * Shows a dialog prompting the user for a contact name before inserting.
     */
    private fun showNamePromptDialog(
        fingerprint: String,
        algorithm: String,
        der: ByteArray,
        source: String,
        suggestedName: String? = null
    ) {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            )
        }

        // Show fingerprint preview
        val fingerprintPreview = TextView(this).apply {
            text = getString(
                R.string.contact_fingerprint,
                formatFingerprint(fingerprint).take(23) + "..."
            )
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 4)
            }
        }
        dialogLayout.addView(fingerprintPreview)

        val algorithmPreview = TextView(this).apply {
            text = getString(R.string.contact_algorithm, algorithm)
            textSize = 12f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 12)
            }
        }
        dialogLayout.addView(algorithmPreview)

        val nameInput = EditText(this).apply {
            hint = getString(R.string.contact_name_hint)
            setSingleLine()
            suggestedName?.let {
                setText(it)
                setSelection(it.length)
            }
        }
        dialogLayout.addView(nameInput)

        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.contact_name_prompt))
            .setView(dialogLayout)
            .setPositiveButton(getString(R.string.contact_import_action)) { _, _ ->
                val name = nameInput.text.toString().trim()
                    .ifBlank { getString(R.string.contact_default_name) }
                insertContact(name, der, fingerprint, algorithm, source)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Inserts a new contact into the database.
     */
    private fun insertContact(
        name: String,
        der: ByteArray,
        fingerprint: String,
        algorithm: String,
        source: String
    ) {
        lifecycleScope.launch {
            try {
                val entity = ContactEntity(
                    name = name,
                    publicKeyDer = der,
                    publicKeyFingerprint = fingerprint,
                    algorithm = algorithm,
                    importedAt = System.currentTimeMillis(),
                    source = source
                )
                withContext(Dispatchers.IO) {
                    contactDao.insert(entity)
                }

                AuditLogger.logContactImported(
                    name = name,
                    fingerprint = fingerprint,
                    source = source
                )

                Snackbar.make(
                    rootLayout,
                    getString(R.string.contact_imported),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: android.database.sqlite.SQLiteConstraintException) {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.contact_import_duplicate),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                android.util.Log.e("ContactManagement", "Contact import failed", e)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.contact_import_error, e.message ?: "Unknown error"),
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    // -------------------------------------------------------------------------
    // Contact Detail Dialog
    // -------------------------------------------------------------------------

    /**
     * Shows a detail dialog for a contact with fingerprint, algorithm, source,
     * imported date, and a delete button.
     */
    private fun showContactDetailDialog(contact: ContactEntity) {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 16),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 24),
                UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            )
        }

        // Fingerprint
        val fingerprintLabel = TextView(this).apply {
            text = getString(
                R.string.contact_fingerprint,
                formatFingerprint(contact.publicKeyFingerprint)
            )
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            }
        }
        dialogLayout.addView(fingerprintLabel)

        // Algorithm
        val algorithmLabel = TextView(this).apply {
            text = getString(R.string.contact_algorithm, contact.algorithm)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            }
        }
        dialogLayout.addView(algorithmLabel)

        // Source
        val sourceLabel = TextView(this).apply {
            text = getString(R.string.contact_source, contact.source)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@ContactManagementActivity, 8)
            }
        }
        dialogLayout.addView(sourceLabel)

        // Imported date
        val importedLabel = TextView(this).apply {
            text = getString(
                R.string.contact_imported_date,
                dateFormat.format(Date(contact.importedAt))
            )
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@ContactManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        dialogLayout.addView(importedLabel)

        MaterialAlertDialogBuilder(this)
            .setTitle(contact.name)
            .setView(dialogLayout)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(getString(R.string.contact_delete_confirm)) { _, _ ->
                showDeleteConfirmation(contact)
            }
            .show()
    }

    // -------------------------------------------------------------------------
    // Delete Operations
    // -------------------------------------------------------------------------

    /**
     * Shows delete confirmation dialog for a contact.
     */
    private fun showDeleteConfirmation(contact: ContactEntity) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.contact_delete_title))
            .setMessage(getString(R.string.contact_delete_message, contact.name))
            .setPositiveButton(getString(R.string.contact_delete_confirm)) { _, _ ->
                deleteContact(contact)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Deletes a contact from the database.
     */
    private fun deleteContact(contact: ContactEntity) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    contactDao.deleteByFingerprint(contact.publicKeyFingerprint)
                }

                AuditLogger.logContactDeleted(
                    name = contact.name,
                    fingerprint = contact.publicKeyFingerprint
                )

                Snackbar.make(
                    rootLayout,
                    getString(R.string.contact_deleted),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                android.util.Log.e("ContactManagement", "Contact deletion failed", e)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.contact_import_error, e.message ?: "Unknown error"),
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Shows an error message via Snackbar.
     */
    private fun showError(message: String) {
        Snackbar.make(
            rootLayout,
            getString(R.string.contact_import_error, message),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    // -------------------------------------------------------------------------
    // RecyclerView Adapter
    // -------------------------------------------------------------------------

    /**
     * RecyclerView adapter for contact cards using DiffUtil.
     */
    inner class ContactListAdapter :
        ListAdapter<ContactEntity, ContactListAdapter.ViewHolder>(ContactDiffCallback()) {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(buildContactCard(parent.context))
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }

        /**
         * Builds a contact card layout programmatically.
         */
        private fun buildContactCard(context: android.content.Context): MaterialCardView {
            val card = PremiumCardFactory.createElevatedCard(context).apply {
                (layoutParams as LinearLayout.LayoutParams).apply {
                    setMargins(
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 6),
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 6)
                    )
                }
            }

            val content = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                setPadding(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 14),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 14)
                )
                gravity = Gravity.CENTER_VERTICAL
            }

            // Circular icon container with gradient
            val iconContainer = FrameLayout(context).apply {
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 48),
                    UIHelpers.dpToPxInt(context, 48)
                ).apply {
                    marginEnd = UIHelpers.dpToPxInt(context, 14)
                }
                tag = "iconContainer"
            }

            val iconView = ImageView(context).apply {
                setImageResource(R.drawable.ic_key_modern)
                layoutParams = FrameLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 28),
                    UIHelpers.dpToPxInt(context, 28)
                ).apply {
                    gravity = Gravity.CENTER
                }
                imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(context, R.color.on_primary)
                )
                tag = "icon"
            }

            iconContainer.addView(iconView)
            content.addView(iconContainer)

            // Info column
            val infoColumn = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f
                )
            }

            val nameText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_TitleMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                tag = "name"
            }
            infoColumn.addView(nameText)

            // Algorithm and fingerprint row
            val metaRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 2)
                }
                gravity = Gravity.CENTER_VERTICAL
            }

            val algorithmText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    androidx.appcompat.R.attr.colorPrimary
                ))
                typeface = Typeface.DEFAULT_BOLD
                tag = "algorithm"
            }
            metaRow.addView(algorithmText)

            val separatorText = TextView(context).apply {
                text = "  \u2022  "
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }
            metaRow.addView(separatorText)

            val fingerprintText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                typeface = Typeface.MONOSPACE
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                tag = "fingerprint"
            }
            metaRow.addView(fingerprintText)
            infoColumn.addView(metaRow)

            // Imported date row
            val dateRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 4)
                }
                tag = "dateRow"
            }

            val dateText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelSmall
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                tag = "importedDate"
            }
            dateRow.addView(dateText)
            infoColumn.addView(dateRow)

            content.addView(infoColumn)

            // Chevron
            val chevron = ImageView(context).apply {
                setImageResource(R.drawable.ic_chevron_right)
                imageTintList = ColorStateList.valueOf(
                    UIHelpers.resolveThemeColor(
                        context,
                        com.google.android.material.R.attr.colorOutlineVariant
                    )
                )
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 24),
                    UIHelpers.dpToPxInt(context, 24)
                )
            }
            content.addView(chevron)

            card.addView(content)
            return card
        }

        inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

            private val iconContainer: FrameLayout = itemView.findViewWithTag("iconContainer")
            private val nameView: TextView = itemView.findViewWithTag("name")
            private val algorithmView: TextView = itemView.findViewWithTag("algorithm")
            private val fingerprintView: TextView = itemView.findViewWithTag("fingerprint")
            private val importedDateView: TextView = itemView.findViewWithTag("importedDate")

            fun bind(contact: ContactEntity) {
                // Set gradient background on icon container
                val gradientStart = ContextCompat.getColor(
                    itemView.context, R.color.gradient_security_start
                )
                val gradientEnd = ContextCompat.getColor(
                    itemView.context, R.color.gradient_security_end
                )
                val gradient = GradientDrawable(
                    GradientDrawable.Orientation.TL_BR,
                    intArrayOf(gradientStart, gradientEnd)
                )
                gradient.cornerRadius = UIHelpers.dpToPx(itemView.context, 24f)
                iconContainer.background = gradient

                // Set text fields
                nameView.text = contact.name
                algorithmView.text = contact.algorithm

                // Show fingerprint preview (first 8 chars formatted)
                val fpFormatted = formatFingerprint(contact.publicKeyFingerprint)
                fingerprintView.text = if (fpFormatted.length > 14) {
                    fpFormatted.substring(0, 14) + "..."
                } else {
                    fpFormatted
                }

                importedDateView.text = getString(
                    R.string.contact_imported_date,
                    dateFormat.format(Date(contact.importedAt))
                )

                // Click handler opens detail dialog
                itemView.setOnClickListener {
                    showContactDetailDialog(contact)
                }
            }
        }
    }

    /**
     * DiffUtil callback for efficient contact list updates.
     */
    class ContactDiffCallback : DiffUtil.ItemCallback<ContactEntity>() {
        override fun areItemsTheSame(
            oldItem: ContactEntity,
            newItem: ContactEntity
        ): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(
            oldItem: ContactEntity,
            newItem: ContactEntity
        ): Boolean {
            return oldItem == newItem
        }
    }
}

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
import android.content.ClipData
import android.content.ComponentName
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.IBinder
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathCredentialWithCode
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.remote.ConnectedDesktop
import com.automatethethings.xkey.remote.RemoteOathClient
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/**
 * Premium activity for managing OATH (TOTP/HOTP) authenticator credentials.
 *
 * Features a gradient toolbar, hero summary card with credential count and
 * type badges, premium card-based list items with live OTP codes, scroll-aware
 * FAB, and swipe-to-delete. Fully programmatic UI following the
 * KeyManagementActivity pattern.
 */
class OathActivity : AppCompatActivity() {

    companion object {
        private const val FAB_ANIMATION_DURATION = 250L
    }

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private lateinit var repository: OathRepository
    private lateinit var adapter: OathAdapter

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var badgeContainer: LinearLayout
    private lateinit var fab: ExtendedFloatingActionButton

    private var isFabVisible = true

    // Desktop OATH (remote.oathAdd / remote.oathGenerate). The service is
    // bound without BIND_AUTO_CREATE: with no desktop connected the screen
    // behaves exactly as before.
    private var gattService: XKeyGattService? = null
    private var serviceBindRequested = false
    private lateinit var desktopActions: OathDesktopActions

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            gattService = (binder as? XKeyGattService.LocalBinder)?.getService()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
        }
    }

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val uri = result.data?.getStringExtra(QrScannerActivity.EXTRA_SCANNED_URI)
            if (uri != null && uri.startsWith("otpauth://")) {
                importScannedUri(uri)
            }
        }
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            launchQrScanner()
        } else {
            Snackbar.make(
                rootLayout,
                R.string.error_permission_denied,
                Snackbar.LENGTH_SHORT
            ).show()
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val db = XKeyDatabase.getInstance(this)
        repository = OathRepository(db.oathCredentialDao(), OathSecretManager())
        desktopActions = OathDesktopActions(
            desktop = { gattService?.connectedDesktop() },
            links = PrefsDesktopOathLinks(
                getSharedPreferences(PrefsDesktopOathLinks.PREFS_NAME, Context.MODE_PRIVATE)
            ),
            secretOf = { entity -> OathSecretManager().decryptSecret(entity.secretEncrypted) }
        )
        serviceBindRequested = bindService(
            Intent(this, XKeyGattService::class.java),
            serviceConnection,
            0
        )

        buildUI()
        setContentView(rootLayout)
        observeCredentials()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressedDispatcher.onBackPressed()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // -------------------------------------------------------------------------
    // UI Construction
    // -------------------------------------------------------------------------

    private fun buildUI() {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@OathActivity,
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

        buildPremiumToolbar()
        buildSummaryHeroCard()
        buildKeyList()
        buildEmptyState()
        buildFab()

        rootLayout.addView(contentLayout)
        rootLayout.addView(fab)
    }

    private fun buildPremiumToolbar() {
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
                UIHelpers.resolveActionBarSize(this@OathActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.oath_title)
            setTitleTextColor(ContextCompat.getColor(this@OathActivity, R.color.on_primary))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.oath_card_description)
            setTextColor(ContextCompat.getColor(
                this@OathActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@OathActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@OathActivity, 16),
                UIHelpers.dpToPxInt(this@OathActivity, 12)
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

    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@OathActivity, 100)
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
                UIHelpers.dpToPxInt(this@OathActivity, 20),
                UIHelpers.dpToPxInt(this@OathActivity, 20),
                UIHelpers.dpToPxInt(this@OathActivity, 20),
                UIHelpers.dpToPxInt(this@OathActivity, 20)
            )
        }

        // Left section
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            gravity = Gravity.CENTER_VERTICAL
        }

        val vaultIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.ic_lock_idle_lock)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@OathActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@OathActivity, 64),
                UIHelpers.dpToPxInt(this@OathActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@OathActivity, 16)
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
            setTextColor(ContextCompat.getColor(this@OathActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.oath_count_zero)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@OathActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(vaultIcon)
        countSection.addView(textSection)

        // Right section: badges
        badgeContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
        }

        cardContent.addView(countSection)
        cardContent.addView(badgeContainer)
        summaryCard.addView(cardContent)
        contentLayout.addView(summaryCard)
    }

    private fun buildKeyList() {
        adapter = OathAdapter(
            onItemClick = { item -> copyCodeToClipboard(item) },
            onItemLongClick = { item ->
                showContextMenu(item)
                true
            }
        )

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@OathActivity)
            this.adapter = this@OathActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@OathActivity, 12),
                UIHelpers.dpToPxInt(this@OathActivity, 4),
                UIHelpers.dpToPxInt(this@OathActivity, 12),
                UIHelpers.dpToPxInt(this@OathActivity, 88)
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

        setupSwipeToDelete()
        contentLayout.addView(recyclerView)
    }

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
                UIHelpers.dpToPxInt(this@OathActivity, 48),
                UIHelpers.dpToPxInt(this@OathActivity, 48),
                UIHelpers.dpToPxInt(this@OathActivity, 48),
                UIHelpers.dpToPxInt(this@OathActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.ic_lock_idle_lock)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@OathActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@OathActivity, 96),
                UIHelpers.dpToPxInt(this@OathActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@OathActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.oath_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@OathActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@OathActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.oath_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@OathActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        contentLayout.addView(emptyStateContainer)
    }

    private fun buildFab() {
        fab = ExtendedFloatingActionButton(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.BOTTOM or Gravity.END
                setMargins(
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 16),
                    UIHelpers.dpToPxInt(this@OathActivity, 16)
                )
            }
            text = getString(R.string.oath_add_choose_method)
            setIconResource(android.R.drawable.ic_input_add)
            backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@OathActivity, R.color.secondary)
            )
            setTextColor(ContextCompat.getColor(this@OathActivity, R.color.on_secondary))
            iconTint = ColorStateList.valueOf(
                ContextCompat.getColor(this@OathActivity, R.color.on_secondary)
            )
            setOnClickListener { showAddMethodChooser() }
        }
    }

    private fun showFab() {
        isFabVisible = true
        fab.extend()
        fab.animate()
            .translationY(0f)
            .alpha(1f)
            .setDuration(FAB_ANIMATION_DURATION)
            .start()
    }

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
    // Swipe to Delete
    // -------------------------------------------------------------------------

    private fun setupSwipeToDelete() {
        val swipeCallback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT) {
            private val paint = Paint().apply {
                color = ContextCompat.getColor(this@OathActivity, android.R.color.holo_red_dark)
            }
            private val textPaint = Paint().apply {
                color = android.graphics.Color.WHITE
                textSize = 40f
                isAntiAlias = true
                textAlign = Paint.Align.RIGHT
            }
            private val cornerRadius = 16f * resources.displayMetrics.density

            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ) = false

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                val item = adapter.currentList[position]
                adapter.notifyItemChanged(position)
                showDeleteConfirmation(item)
            }

            override fun onChildDraw(
                c: Canvas, recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                dX: Float, dY: Float, actionState: Int, isCurrentlyActive: Boolean
            ) {
                if (dX < 0) {
                    val itemView = viewHolder.itemView
                    val rect = RectF(
                        itemView.right + dX, itemView.top.toFloat(),
                        itemView.right.toFloat(), itemView.bottom.toFloat()
                    )
                    c.drawRoundRect(rect, cornerRadius, cornerRadius, paint)
                    val textY = itemView.top + (itemView.height / 2f) + (textPaint.textSize / 3f)
                    c.drawText(
                        getString(R.string.oath_context_delete),
                        itemView.right - 48f * resources.displayMetrics.density,
                        textY, textPaint
                    )
                }
                super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive)
            }
        }
        ItemTouchHelper(swipeCallback).attachToRecyclerView(recyclerView)
    }

    // -------------------------------------------------------------------------
    // Data Observation
    // -------------------------------------------------------------------------

    private fun observeCredentials() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                val ticker: Flow<Unit> = flow {
                    while (true) {
                        emit(Unit)
                        delay(1000L)
                    }
                }

                ticker.flatMapLatest {
                    repository.observeAll()
                }.collectLatest { credentials ->
                    updateUI(credentials)
                    updateSummaryCard(credentials)
                }
            }
        }
    }

    private fun updateUI(credentials: List<OathCredentialWithCode>) {
        if (credentials.isEmpty()) {
            emptyStateContainer.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else {
            emptyStateContainer.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
        }
        adapter.submitList(credentials)
    }

    private fun updateSummaryCard(credentials: List<OathCredentialWithCode>) {
        totalCountText.text = credentials.size.toString()
        totalLabelText.text = when {
            credentials.isEmpty() -> getString(R.string.oath_count_zero)
            credentials.size == 1 -> getString(R.string.oath_count_one)
            else -> getString(R.string.oath_count, credentials.size)
        }

        badgeContainer.removeAllViews()

        val totpCount = credentials.count { it.credential.oathType == "TOTP" }
        val hotpCount = credentials.count { it.credential.oathType == "HOTP" }

        badgeContainer.addView(createSummaryBadge(
            "$totpCount TOTP",
            ContextCompat.getColor(this, R.color.primary_60)
        ))
        badgeContainer.addView(createSummaryBadge(
            "$hotpCount HOTP",
            ContextCompat.getColor(this, R.color.tertiary_60)
        ))
    }

    private fun createSummaryBadge(text: String, bgColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@OathActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@OathActivity, 10),
                UIHelpers.dpToPxInt(this@OathActivity, 4),
                UIHelpers.dpToPxInt(this@OathActivity, 10),
                UIHelpers.dpToPxInt(this@OathActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(bgColor, 0.3f),
                UIHelpers.dpToPx(this@OathActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@OathActivity, 4)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    private fun copyCodeToClipboard(item: OathCredentialWithCode) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("OTP Code", item.code)
        clipboard.setPrimaryClip(clip)

        Snackbar.make(
            rootLayout,
            R.string.oath_code_copied,
            Snackbar.LENGTH_SHORT
        ).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (serviceBindRequested) {
            unbindService(serviceConnection)
            serviceBindRequested = false
        }
    }

    private fun showContextMenu(item: OathCredentialWithCode) {
        val displayName = buildString {
            item.credential.issuer?.let { append("$it: ") }
            append(item.credential.accountName)
        }
        val desktopEntries = desktopActions.menuEntries(item.credential)
        val labels = mutableListOf(
            getString(R.string.oath_context_view_details),
            getString(R.string.oath_context_delete)
        )
        desktopEntries.forEach { entry ->
            labels += when (entry) {
                OathDesktopActions.Entry.COPY -> getString(R.string.oath_context_copy_to_desktop)
                OathDesktopActions.Entry.DESKTOP_CODE -> getString(R.string.oath_context_desktop_code)
            }
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(displayName)
            .setItems(labels.toTypedArray()) { _, which ->
                when (which) {
                    0 -> showCredentialDetails(item)
                    1 -> showDeleteConfirmation(item)
                    else -> when (desktopEntries.getOrNull(which - 2)) {
                        OathDesktopActions.Entry.COPY -> copyToDesktop(item.credential)
                        OathDesktopActions.Entry.DESKTOP_CODE -> showDesktopCode(item.credential)
                        null -> Unit
                    }
                }
            }
            .show()
    }

    private fun copyToDesktop(credential: OathCredentialEntity) {
        lifecycleScope.launch {
            showDesktopOutcome(desktopActions.copyToDesktop(credential))
        }
    }

    private fun showDesktopCode(credential: OathCredentialEntity) {
        lifecycleScope.launch {
            showDesktopOutcome(desktopActions.desktopCode(credential))
        }
    }

    private fun showDesktopOutcome(outcome: OathDesktopActions.Outcome) {
        when (outcome) {
            is OathDesktopActions.Outcome.Code -> {
                val expiry = outcome.expiresIn
                    ?.let { getString(R.string.oath_desktop_code_expires, it) }
                    ?: getString(R.string.oath_desktop_code_no_expiry)
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.oath_desktop_code_title)
                    .setMessage("${outcome.code}\n\n$expiry")
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            is OathDesktopActions.Outcome.Copied ->
                Snackbar.make(rootLayout, R.string.oath_desktop_copied, Snackbar.LENGTH_SHORT).show()
            OathDesktopActions.Outcome.NotConnected ->
                Snackbar.make(rootLayout, R.string.oath_desktop_not_connected, Snackbar.LENGTH_SHORT).show()
            OathDesktopActions.Outcome.NotOnDesktop ->
                Snackbar.make(rootLayout, R.string.oath_desktop_not_linked, Snackbar.LENGTH_SHORT).show()
            is OathDesktopActions.Outcome.Failed ->
                Snackbar.make(
                    rootLayout,
                    getString(R.string.oath_desktop_failed, outcome.message),
                    Snackbar.LENGTH_LONG
                ).show()
        }
    }

    private fun showCredentialDetails(item: OathCredentialWithCode) {
        val cred = item.credential
        val dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val hPad = (24 * resources.displayMetrics.density).toInt()
            val vPad = (16 * resources.displayMetrics.density).toInt()
            setPadding(hPad, vPad, hPad, 0)
        }

        fun addRow(label: String, value: String) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                val bottomPad = (12 * resources.displayMetrics.density).toInt()
                setPadding(0, 0, 0, bottomPad)
            }

            row.addView(TextView(this).apply {
                text = label
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelSmall)
                setTextColor(ContextCompat.getColor(this@OathActivity, android.R.color.darker_gray))
            })

            row.addView(TextView(this).apply {
                text = value
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            })

            container.addView(row)
        }

        cred.issuer?.let { addRow(getString(R.string.oath_detail_issuer), it) }
        addRow(getString(R.string.oath_detail_account), cred.accountName)
        addRow(getString(R.string.oath_detail_type), cred.oathType)
        addRow(getString(R.string.oath_detail_algorithm), cred.algorithm)
        addRow(getString(R.string.oath_detail_digits), cred.digits.toString())

        if (cred.oathType == "TOTP") {
            addRow(
                getString(R.string.oath_detail_period),
                getString(R.string.oath_detail_period_value, cred.periodSeconds)
            )
        } else {
            addRow(getString(R.string.oath_detail_counter), cred.counter.toString())
        }

        addRow(getString(R.string.oath_detail_source), cred.source.replaceFirstChar { it.uppercase() })
        addRow(getString(R.string.oath_detail_created), dateFormat.format(Date(cred.createdAt)))
        addRow(
            getString(R.string.oath_detail_last_used),
            if (cred.lastUsedAt != null) dateFormat.format(Date(cred.lastUsedAt))
            else getString(R.string.oath_detail_never_used)
        )
        addRow(
            getString(R.string.oath_detail_use_count),
            getString(R.string.oath_detail_times_used, cred.useCount)
        )
        addRow(
            getString(R.string.oath_detail_security),
            getString(R.string.oath_detail_security_value)
        )

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.oath_detail_title)
            .setView(container)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showDeleteConfirmation(item: OathCredentialWithCode) {
        val displayName = buildString {
            item.credential.issuer?.let { append("$it: ") }
            append(item.credential.accountName)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.oath_delete_title)
            .setMessage(getString(R.string.oath_delete_prompt, displayName))
            .setPositiveButton(R.string.oath_context_delete) { _, _ ->
                lifecycleScope.launch {
                    try {
                        repository.deleteCredential(item.credential.oathId)
                        Snackbar.make(
                            rootLayout,
                            R.string.oath_credential_deleted,
                            Snackbar.LENGTH_SHORT
                        ).show()
                    } catch (e: Exception) {
                        showError(e)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Surfaces a failure verbatim. Import rejections carry the reason the
     * credential was refused — which characters of a secret were invalid, for
     * instance — and that reason is the only thing that lets a user fix it.
     */
    private fun showError(error: Throwable) {
        Snackbar.make(
            rootLayout,
            getString(R.string.oath_error, error.message ?: error.javaClass.simpleName),
            Snackbar.LENGTH_LONG
        ).show()
    }

    // -------------------------------------------------------------------------
    // Add Credential
    // -------------------------------------------------------------------------

    private fun showAddMethodChooser() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.oath_add_choose_method)
            .setItems(
                arrayOf(
                    getString(R.string.oath_add_scan_qr),
                    getString(R.string.oath_add_enter_manually)
                )
            ) { _, which ->
                when (which) {
                    0 -> requestCameraAndScan()
                    1 -> showManualEntryDialog()
                }
            }
            .show()
    }

    private fun requestCameraAndScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            launchQrScanner()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun launchQrScanner() {
        val intent = Intent(this, QrScannerActivity::class.java)
        qrScanLauncher.launch(intent)
    }

    private fun importScannedUri(uri: String) {
        lifecycleScope.launch {
            try {
                repository.importFromUri(uri)
                Snackbar.make(
                    rootLayout,
                    R.string.oath_credential_added,
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                showError(e)
            }
        }
    }

    private fun showManualEntryDialog() {
        AddOathDialog.show(this) { issuer, accountName, secret, type, algorithm, digits, period ->
            lifecycleScope.launch {
                try {
                    repository.importFromUri(
                        buildOtpauthUri(
                            issuer = issuer,
                            accountName = accountName,
                            secret = secret,
                            type = type,
                            algorithm = algorithm,
                            digits = digits,
                            period = period
                        )
                    )
                    Snackbar.make(
                        rootLayout,
                        R.string.oath_credential_added,
                        Snackbar.LENGTH_SHORT
                    ).show()
                } catch (e: Exception) {
                    showError(e)
                }
            }
        }
    }

    /**
     * Assembles the `otpauth://` URI the importer parses, from hand-entered
     * values.
     *
     * Built with [Uri.Builder] rather than by concatenation so that the label
     * and the parameters are percent-encoded: an issuer or account containing
     * `&`, `?`, `#`, or `=` — all of them legal in a display name and an email
     * address — would otherwise be read back as URI structure and corrupt every
     * field after it.
     */
    private fun buildOtpauthUri(
        issuer: String?,
        accountName: String,
        secret: String,
        type: String,
        algorithm: String,
        digits: Int,
        period: Int
    ): String {
        val label = if (issuer != null) "$issuer:$accountName" else accountName
        return Uri.Builder()
            .scheme("otpauth")
            .authority(type.lowercase())
            .appendPath(label)
            .appendQueryParameter("secret", secret)
            .apply { if (issuer != null) appendQueryParameter("issuer", issuer) }
            .appendQueryParameter("algorithm", algorithm)
            .appendQueryParameter("digits", digits.toString())
            .appendQueryParameter("period", period.toString())
            .build()
            .toString()
    }
}

/**
 * (desktop, phone oathId) -> desktop credential_id, learned from
 * remote.oathAdd replies. A desktop is named by its Noise-authenticated static
 * key ([ConnectedDesktop.peerKeyHex]): a credential ID means nothing on any
 * other desktop.
 */
interface DesktopOathLinks {
    fun get(peerKeyHex: String, oathId: String): String?
    fun put(peerKeyHex: String, oathId: String, desktopId: String)
}

/** [DesktopOathLinks] in private SharedPreferences (IDs only, no secrets). */
class PrefsDesktopOathLinks(private val prefs: SharedPreferences) : DesktopOathLinks {
    override fun get(peerKeyHex: String, oathId: String): String? =
        prefs.getString(key(peerKeyHex, oathId), null)

    override fun put(peerKeyHex: String, oathId: String, desktopId: String) {
        prefs.edit().putString(key(peerKeyHex, oathId), desktopId).apply()
    }

    /** Hex has no '/', so the first one ends the peer key. */
    private fun key(peerKeyHex: String, oathId: String) = "${peerKeyHex.lowercase()}/$oathId"

    companion object {
        const val PREFS_NAME = "oath_desktop_links"
    }
}

/**
 * The OATH screen's desktop actions, kept free of Android types so they unit
 * test on the JVM. [desktop] is null whenever no desktop has an established
 * session; then no entry is offered and nothing is sent. Links are read and
 * written for the desktop [desktop] returns at the time of each call.
 */
class OathDesktopActions(
    private val desktop: () -> ConnectedDesktop?,
    private val links: DesktopOathLinks,
    private val secretOf: suspend (OathCredentialEntity) -> ByteArray
) {
    enum class Entry { COPY, DESKTOP_CODE }

    sealed interface Outcome {
        data class Copied(val desktopId: String) : Outcome
        data class Code(val code: String, val expiresIn: Int?) : Outcome
        data object NotConnected : Outcome
        data object NotOnDesktop : Outcome
        data class Failed(val message: String) : Outcome
    }

    fun isConnected(): Boolean = desktop() != null

    /** Desktop entries for [credential]'s context menu; empty with no desktop. */
    fun menuEntries(credential: OathCredentialEntity): List<Entry> {
        val peer = desktop() ?: return emptyList()
        return if (links.get(peer.peerKeyHex, credential.oathId) != null) {
            listOf(Entry.COPY, Entry.DESKTOP_CODE)
        } else {
            listOf(Entry.COPY)
        }
    }

    /** Sends remote.oathAdd for [credential] and remembers the desktop ID. */
    suspend fun copyToDesktop(credential: OathCredentialEntity): Outcome {
        val peer = desktop() ?: return Outcome.NotConnected
        val remote = RemoteOathClient(peer.sender, peer.router)
        return try {
            val raw = secretOf(credential)
            val secret = try {
                RemoteOathClient.base32Chars(raw)
            } finally {
                raw.fill(0)
            }
            val result = remote.oathAdd(
                RemoteOathClient.Credential(
                    name = credential.oathId,
                    issuer = credential.issuer,
                    accountName = credential.accountName,
                    secret = secret,
                    type = credential.oathType.lowercase(),
                    algorithm = credential.algorithm.uppercase(),
                    digits = credential.digits,
                    period = credential.periodSeconds,
                    counter = credential.counter
                )
            )
            links.put(peer.peerKeyHex, credential.oathId, result.credentialId)
            Outcome.Copied(result.credentialId)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Outcome.Failed(e.message ?: e.javaClass.simpleName)
        }
    }

    /** Sends remote.oathGenerate for the desktop copy of [credential]. */
    suspend fun desktopCode(credential: OathCredentialEntity): Outcome {
        val peer = desktop() ?: return Outcome.NotConnected
        val desktopId = links.get(peer.peerKeyHex, credential.oathId) ?: return Outcome.NotOnDesktop
        return try {
            val result = RemoteOathClient(peer.sender, peer.router).oathGenerate(desktopId)
            Outcome.Code(result.code, result.expiresIn)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Outcome.Failed(e.message ?: e.javaClass.simpleName)
        }
    }
}

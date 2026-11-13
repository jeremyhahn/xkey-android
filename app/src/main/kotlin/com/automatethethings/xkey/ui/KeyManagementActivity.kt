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

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.KeyStoreSyncManager
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.google.android.material.card.MaterialCardView
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Premium Key Vault activity for managing cryptographic keys.
 *
 * Provides a professional, banking-grade UI experience for managing keys stored by xKey.
 * Features elegant gradient toolbars, animated filter chips, premium key cards with
 * type-specific color coding, and smooth animations throughout.
 *
 * Features:
 * - Hero summary card with key statistics and type breakdown badges
 * - Premium pill-shaped filter chips with gold selection state
 * - Elevated key cards with gradient icon containers and security badges
 * - Floating action button with scroll-aware visibility
 * - Smooth RecyclerView animations with DiffUtil
 * - Long-press context menu for key actions
 */
class KeyManagementActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /** Menu item ID for sharing settings (FIDO2 keys only). */
        private const val MENU_SHARE_SETTINGS = 1
        /** Menu item ID for viewing key details. */
        private const val MENU_VIEW_DETAILS = 2
        /** Menu item ID for exporting public key. */
        private const val MENU_EXPORT_PUBLIC = 3
        /** Menu item ID for deleting a key. */
        private const val MENU_DELETE = 4

        /** Animation duration for chip selection. */
        private const val CHIP_ANIMATION_DURATION = 200L
        /** Animation duration for FAB show/hide. */
        private const val FAB_ANIMATION_DURATION = 250L

        /** Key-factory algorithms tried when decoding a generated SPKI public key. */
        private val KEY_FACTORY_ALGORITHMS = listOf("EC", "RSA")

    }

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private val keyDao by lazy { XKeyDatabase.getInstance(this).keyDao() }
    private val keyPolicyStore by lazy { KeyPolicyStore.of(XKeyDatabase.getInstance(this)) }
    private val credentialDao by lazy { XKeyDatabase.getInstance(this).credentialMetadataDao() }
    private val keystoreManager by lazy { KeystoreManager(this) }
    private val syncManager by lazy {
        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, keyPolicyStore)
    }

    // -------------------------------------------------------------------------
    // UI Components
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var filterScrollView: HorizontalScrollView
    private lateinit var chipContainer: LinearLayout
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var fab: ExtendedFloatingActionButton
    private lateinit var adapter: KeyListAdapter

    // Summary card views
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var badgeContainer: LinearLayout

    // Filter chip tracking
    private val filterChips = mutableMapOf<String?, View>()
    private var currentFilter: String? = null
    private var allKeys: List<KeyEntity> = emptyList()

    // FAB visibility tracking
    private var isFabVisible = true

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUI()
        setContentView(rootLayout)
        observeKeys()
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

    /**
     * Builds the complete premium UI programmatically.
     */
    private fun buildUI() {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@KeyManagementActivity,
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
        buildPremiumFilterBar()
        buildKeyList()
        buildEmptyState()
        buildFab()

        rootLayout.addView(contentLayout)
        rootLayout.addView(fab)
    }

    /**
     * Creates the premium toolbar with gradient background.
     */
    private fun buildPremiumToolbar() {
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Apply gradient background
        val gradientStart = ContextCompat.getColor(this, R.color.gradient_primary_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_primary_end)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(gradientStart, gradientEnd)
        )
        toolbarContainer.background = gradient

        // Toolbar
        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@KeyManagementActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.key_vault_title)
            setTitleTextColor(ContextCompat.getColor(this@KeyManagementActivity, R.color.on_primary))
            elevation = 0f
        }

        // Subtitle
        val subtitle = TextView(this).apply {
            text = getString(R.string.key_vault_subtitle)
            setTextColor(ContextCompat.getColor(
                this@KeyManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 12)
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
     * Creates the hero summary card with key statistics.
     */
    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@KeyManagementActivity, 100)
        }

        // Apply gradient background
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
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20)
            )
        }

        // Left section: Key icon and count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        // Key vault icon
        val vaultIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_modern)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@KeyManagementActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 64),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@KeyManagementActivity, 16)
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
            setTextColor(ContextCompat.getColor(this@KeyManagementActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.key_vault_keys_label)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@KeyManagementActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(vaultIcon)
        countSection.addView(textSection)

        // Right section: Type breakdown badges
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

    /**
     * Creates a summary badge for key type counts.
     */
    private fun createSummaryBadge(text: String, bgColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@KeyManagementActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 10),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 4),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 10),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(bgColor, 0.3f),
                UIHelpers.dpToPx(this@KeyManagementActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 4)
            }
        }
    }

    /**
     * Creates the premium pill-shaped filter chips.
     */
    private fun buildPremiumFilterBar() {
        filterScrollView = HorizontalScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }

        // Add fade edges
        filterScrollView.isHorizontalFadingEdgeEnabled = true
        filterScrollView.setFadingEdgeLength(UIHelpers.dpToPxInt(this, 32))

        chipContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 8),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
            )
        }

        val filterTypes = listOf(
            null to getString(R.string.key_filter_all),
            "fido2" to getString(R.string.key_filter_fido2),
            "signing" to getString(R.string.key_filter_signing),
            "encryption" to getString(R.string.key_filter_encryption),
            "tls" to getString(R.string.key_filter_tls),
            "ssh" to getString(R.string.key_filter_ssh),
            "ca" to getString(R.string.key_filter_ca),
            "attestation" to getString(R.string.key_filter_attestation),
            "secret" to getString(R.string.key_filter_secret),
            "hmac" to getString(R.string.key_filter_hmac),
            "xkmsd" to getString(R.string.key_filter_remote)
        )

        filterTypes.forEachIndexed { index, (type, label) ->
            val chip = createPremiumFilterChip(label, index == 0)
            chip.setOnClickListener {
                selectFilterChip(type)
            }
            filterChips[type] = chip
            chipContainer.addView(chip)
        }

        filterScrollView.addView(chipContainer)
        contentLayout.addView(filterScrollView)
    }

    /**
     * Creates a premium pill-shaped filter chip.
     */
    private fun createPremiumFilterChip(text: String, isSelected: Boolean): View {
        val chip = TextView(this).apply {
            this.text = text
            textSize = 14f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 10),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 20),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 10)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
            }
        }

        updateChipStyle(chip, isSelected)
        return chip
    }

    /**
     * Updates chip visual style based on selection state.
     */
    private fun updateChipStyle(chip: View, isSelected: Boolean) {
        val textView = chip as TextView

        if (isSelected) {
            // Gold/primary fill for selected state
            val selectedColor = ContextCompat.getColor(this, R.color.secondary)
            val textColor = ContextCompat.getColor(this, R.color.on_secondary)

            textView.setTextColor(textColor)
            textView.background = UIHelpers.createPillDrawable(
                selectedColor,
                UIHelpers.dpToPx(this, 40f)
            )
        } else {
            // Subtle outline for unselected state
            val outlineColor = UIHelpers.resolveThemeColor(
                this,
                com.google.android.material.R.attr.colorOutlineVariant
            )
            val textColor = UIHelpers.resolveThemeColor(
                this,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            )

            textView.setTextColor(textColor)
            textView.background = UIHelpers.createRoundedDrawable(
                android.graphics.Color.TRANSPARENT,
                UIHelpers.dpToPx(this, 20f),
                UIHelpers.dpToPxInt(this, 1),
                outlineColor
            )
        }
    }

    /**
     * Selects a filter chip with animation.
     */
    private fun selectFilterChip(type: String?) {
        // Deselect previous chip
        filterChips[currentFilter]?.let { previousChip ->
            animateChipDeselection(previousChip)
        }

        // Select new chip
        filterChips[type]?.let { newChip ->
            animateChipSelection(newChip)
        }

        currentFilter = type
        applyFilter()
    }

    /**
     * Animates chip selection.
     */
    private fun animateChipSelection(chip: View) {
        val scaleX = ObjectAnimator.ofFloat(chip, View.SCALE_X, 0.95f, 1f)
        val scaleY = ObjectAnimator.ofFloat(chip, View.SCALE_Y, 0.95f, 1f)

        AnimatorSet().apply {
            playTogether(scaleX, scaleY)
            duration = CHIP_ANIMATION_DURATION
            interpolator = DecelerateInterpolator()
            start()
        }

        updateChipStyle(chip, true)
    }

    /**
     * Animates chip deselection.
     */
    private fun animateChipDeselection(chip: View) {
        updateChipStyle(chip, false)
    }

    /**
     * Creates the RecyclerView for displaying the key list.
     */
    private fun buildKeyList() {
        adapter = KeyListAdapter()

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@KeyManagementActivity)
            this.adapter = this@KeyManagementActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 12),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 4),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 12),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 88)
            )
            clipToPadding = false

            // Add scroll listener for FAB visibility
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

        // Add item animator for smooth updates
        recyclerView.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator().apply {
            addDuration = 200
            removeDuration = 200
            moveDuration = 200
            changeDuration = 200
        }

        contentLayout.addView(recyclerView)
    }

    /**
     * Creates the empty state container (content is populated dynamically in applyFilter).
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
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 48),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 48),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 48),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 48)
            )
        }
        contentLayout.addView(emptyStateContainer)
    }

    /**
     * Creates the premium floating action button with gradient styling.
     */
    private fun buildFab() {
        fab = ExtendedFloatingActionButton(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.BOTTOM or Gravity.END
                setMargins(
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@KeyManagementActivity, 16)
                )
            }
            text = getString(R.string.key_create_title)
            setIconResource(android.R.drawable.ic_input_add)
            backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@KeyManagementActivity, R.color.secondary)
            )
            setTextColor(ContextCompat.getColor(this@KeyManagementActivity, R.color.on_secondary))
            iconTint = ColorStateList.valueOf(
                ContextCompat.getColor(this@KeyManagementActivity, R.color.on_secondary)
            )
            setOnClickListener { showCreateKeyDialog() }
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
     * Syncs all key sources and observes keys reactively.
     */
    private fun observeKeys() {
        lifecycleScope.launch {
            try {
                // Owed material deletes first: a tombstoned key is never rediscovered (#193 r9).
                com.automatethethings.xkey.storage.replayKeyDeletions(this@KeyManagementActivity, keyPolicyStore)
                syncManager.syncAll()
            } catch (e: Exception) {
                android.util.Log.w("KeyManagementActivity", "Key sync failed", e)
            }

            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                keyDao.observeAll().collectLatest { keys ->
                    allKeys = keys
                    applyFilter()
                    updateSummaryCard()
                }
            }
        }
        observeUnsavedWithdrawals()
    }

    /**
     * Shows, for as long as one stands, that a withdrawal is held only in
     * the process: a sheet dismissed before its withdrawal was saved leaves
     * it here (#193 r8).
     */
    private fun observeUnsavedWithdrawals() {
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                var shown: com.google.android.material.snackbar.Snackbar? = null
                try {
                    KeySharingPeers.unsavedKeys.collectLatest { keys ->
                        shown?.dismiss()
                        shown = if (keys.isEmpty()) null else com.google.android.material.snackbar.Snackbar.make(
                            findViewById(android.R.id.content),
                            getString(R.string.key_sharing_denial_not_saved),
                            com.google.android.material.snackbar.Snackbar.LENGTH_INDEFINITE,
                        ).also { it.show() }
                    }
                } finally {
                    shown?.dismiss()
                }
            }
        }
    }

    /**
     * Applies the current filter and updates the adapter.
     */
    private fun applyFilter() {
        val filtered = when {
            currentFilter == null -> allKeys
            currentFilter == "xkmsd" -> allKeys.filter { it.source == "xkmsd" }
            else -> allKeys.filter { it.keyType == currentFilter }
        }
        adapter.submitList(filtered)

        if (filtered.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyStateContainer.removeAllViews()

            if (allKeys.isEmpty()) {
                // Vault is truly empty
                buildEmptyVaultContent()
            } else {
                // Filter has no results
                buildFilterEmptyContent()
            }
            emptyStateContainer.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyStateContainer.visibility = View.GONE
        }
    }

    /**
     * Builds the empty vault state (no keys at all).
     */
    private fun buildEmptyVaultContent() {
        val emptyIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_modern)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@KeyManagementActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 96),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.key_vault_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@KeyManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.key_vault_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@KeyManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 32)
            }
        }

        val createButton = com.google.android.material.button.MaterialButton(this).apply {
            text = getString(R.string.key_vault_create_first)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { showCreateKeyDialog() }
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        emptyStateContainer.addView(createButton)
    }

    /**
     * Builds the filter empty state (vault has keys, but filter matches none).
     * Shows a context-aware message with option to create the filtered key type.
     */
    private fun buildFilterEmptyContent() {
        val filterName = getFilterDisplayName(currentFilter)

        val infoIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_modern)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@KeyManagementActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 64),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 64)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 24)
            }
        }

        val filterTitle = TextView(this).apply {
            text = getString(R.string.no_keys_for_filter, filterName)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@KeyManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
            }
        }

        val filterDescription = TextView(this).apply {
            text = getString(R.string.no_keys_for_filter_desc, filterName)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@KeyManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 24)
            }
        }

        emptyStateContainer.addView(infoIcon)
        emptyStateContainer.addView(filterTitle)
        emptyStateContainer.addView(filterDescription)

        // Show "Create {type} Key" button for creatable key types
        val creatableType = getCreatableKeyType(currentFilter)
        if (creatableType != null) {
            val createButton = com.google.android.material.button.MaterialButton(this).apply {
                text = getString(R.string.create_key_of_type, filterName)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
                }
                setOnClickListener { showCreateKeyDialog() }
            }
            emptyStateContainer.addView(createButton)
        }

        val clearButton = com.google.android.material.button.MaterialButton(
            this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            text = getString(R.string.clear_filter)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { selectFilterChip(null) }
        }
        emptyStateContainer.addView(clearButton)
    }

    /**
     * Returns the creatable key type for a filter, or null if the type isn't user-creatable.
     * FIDO2 keys are created via registration, CA/attestation are system-generated,
     * and remote keys come from paired devices.
     */
    private fun getCreatableKeyType(filterType: String?): String? = when (filterType) {
        "signing", "tls", "ssh", "encryption", "secret", "hmac" -> filterType
        else -> null // fido2, ca, attestation, xkmsd are not directly creatable
    }

    /**
     * Maps filter type to human-readable display name.
     */
    private fun getFilterDisplayName(filterType: String?): String = when (filterType) {
        "fido2" -> "FIDO2"
        "signing" -> getString(R.string.key_filter_signing)
        "encryption" -> getString(R.string.key_filter_encryption)
        "tls" -> "TLS"
        "ssh" -> "SSH"
        "ca" -> getString(R.string.key_filter_ca)
        "attestation" -> getString(R.string.key_filter_attestation)
        "secret" -> getString(R.string.key_filter_secret)
        "hmac" -> "HMAC"
        "xkmsd" -> getString(R.string.key_filter_remote)
        else -> filterType ?: getString(R.string.key_filter_all)
    }

    /**
     * Updates the hero summary card with key statistics.
     */
    private fun updateSummaryCard() {
        totalCountText.text = allKeys.size.toString()
        totalLabelText.text = if (allKeys.size == 1) {
            getString(R.string.key_vault_key_label)
        } else {
            getString(R.string.key_vault_keys_label)
        }

        // Update fixed type breakdown badges: FIDO2, Signing, Encryption
        badgeContainer.removeAllViews()

        val typeCounts = allKeys.groupingBy { it.keyType }.eachCount()
        val fido2Count = typeCounts["fido2"] ?: 0
        val signingCount = typeCounts["signing"] ?: 0
        val encryptionCount = typeCounts["encryption"] ?: 0

        badgeContainer.addView(createSummaryBadge(
            "$fido2Count FIDO2",
            ContextCompat.getColor(this, R.color.primary_60)
        ))
        badgeContainer.addView(createSummaryBadge(
            "$signingCount ${getString(R.string.key_filter_signing)}",
            ContextCompat.getColor(this, R.color.tertiary_60)
        ))
        badgeContainer.addView(createSummaryBadge(
            "$encryptionCount ${getString(R.string.key_filter_encryption)}",
            ContextCompat.getColor(this, R.color.security_verified)
        ))
    }

    // -------------------------------------------------------------------------
    // Key Operations
    // -------------------------------------------------------------------------

    private data class AlgorithmOption(val display: String, val internal: String)
    private data class PurposeOption(val display: String, val keyType: String, val algorithms: List<AlgorithmOption>)

    private fun buildTlsAlgorithms(): List<AlgorithmOption> {
        val list = mutableListOf(
            AlgorithmOption("ECDSA P-256", "ES256"),
            AlgorithmOption("ECDSA P-384", "ES384"),
            AlgorithmOption("RSA 2048", "RS256"),
            AlgorithmOption("RSA 4096", "RS512")
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            list.add(AlgorithmOption("Ed25519", "Ed25519"))
        }
        return list
    }

    private fun buildSshAlgorithms(): List<AlgorithmOption> = buildTlsAlgorithms()

    /**
     * Shows the create key dialog.
     */
    private fun showCreateKeyDialog() {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 24),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 16),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 24),
                UIHelpers.dpToPxInt(this@KeyManagementActivity, 8)
            )
        }

        val labelInput = EditText(this).apply {
            hint = getString(R.string.key_create_label_hint)
            setSingleLine()
        }
        dialogLayout.addView(labelInput)

        val purposeLabel = TextView(this).apply {
            text = getString(R.string.key_create_purpose)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 12)
            }
        }
        dialogLayout.addView(purposeLabel)

        val purposes = listOf(
            PurposeOption(getString(R.string.key_create_purpose_signing), "signing", listOf(
                AlgorithmOption("ECDSA P-256", "ES256"),
                AlgorithmOption("ECDSA P-384", "ES384"),
                AlgorithmOption("RSA 2048", "RS256")
            )),
            PurposeOption(getString(R.string.key_create_purpose_tls), "tls", buildTlsAlgorithms()),
            PurposeOption(getString(R.string.key_create_purpose_ssh), "ssh", buildSshAlgorithms()),
            PurposeOption(getString(R.string.key_create_purpose_encryption), "encryption", listOf(
                AlgorithmOption("RSA-OAEP 2048", "RSA-OAEP-2048"),
                AlgorithmOption("RSA-OAEP 4096", "RSA-OAEP-4096")
            )),
            PurposeOption(getString(R.string.key_create_purpose_secret), "secret", listOf(
                AlgorithmOption("AES-128", "AES-128"),
                AlgorithmOption("AES-256", "AES-256")
            )),
            PurposeOption(getString(R.string.key_create_purpose_hmac), "hmac", listOf(
                AlgorithmOption("HMAC-SHA256", "HMAC-SHA256"),
                AlgorithmOption("HMAC-SHA512", "HMAC-SHA512")
            ))
        )

        val purposeSpinner = Spinner(this)
        val purposeAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            purposes.map { it.display }
        )
        purposeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        purposeSpinner.adapter = purposeAdapter
        dialogLayout.addView(purposeSpinner)

        val algorithmLabel = TextView(this).apply {
            text = getString(R.string.key_create_algorithm)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 12)
            }
        }
        dialogLayout.addView(algorithmLabel)

        val algorithmSpinner = Spinner(this)
        dialogLayout.addView(algorithmSpinner)

        fun updateAlgorithms() {
            val selected = purposes[purposeSpinner.selectedItemPosition]
            val algAdapter = ArrayAdapter(
                this,
                android.R.layout.simple_spinner_item,
                selected.algorithms.map { it.display }
            )
            algAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            algorithmSpinner.adapter = algAdapter
        }
        updateAlgorithms()

        purposeSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                updateAlgorithms()
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        val biometricSwitch = com.google.android.material.materialswitch.MaterialSwitch(this).apply {
            text = getString(R.string.key_create_biometric)
            isChecked = true
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@KeyManagementActivity, 12)
            }
        }
        dialogLayout.addView(biometricSwitch)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.key_create_title))
            .setView(dialogLayout)
            .setPositiveButton(getString(R.string.key_create_title)) { _, _ ->
                val purpose = purposes[purposeSpinner.selectedItemPosition]
                val algorithmOption = purpose.algorithms[algorithmSpinner.selectedItemPosition]
                val algorithm = algorithmOption.internal
                val label = labelInput.text.toString().ifBlank { "${purpose.display} Key" }
                val biometric = biometricSwitch.isChecked
                createKey(label, purpose.keyType, algorithm, biometric)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Creates a new key.
     */
    private fun createKey(label: String, keyType: String, algorithm: String, biometric: Boolean) {
        lifecycleScope.launch {
            try {
                val keyId = UUID.randomUUID().toString()
                // -1 is the "no authentication required" sentinel; 0 means
                // "authenticate on every use". Passing 0 for an unchecked switch
                // still produced an auth-bound key, so the toggle could not be
                // turned off — and on a device with nothing enrolled, Keystore
                // refuses such a key and creation failed outright.
                val authDuration = if (biometric) 5 else -1
                var publicKeyDer: ByteArray? = null
                var keySizeBits = 0

                // The material write and its row insert in the store's one
                // serialisation of this id's key material (#193 r8).
                keyPolicyStore.withKeyMaterial(keyId, com.automatethethings.xkey.storage.keyMaterialDeleter(this@KeyManagementActivity, keystoreManager)) {
                    when (keyType) {
                        "signing", "tls", "ssh" -> {
                            publicKeyDer = keystoreManager.generateKeyForAlgorithm(keyId, algorithm, authDuration)
                            keySizeBits = actualKeySizeBits(publicKeyDer)
                                ?: nominalKeySizeBits(algorithm)
                        }
                        "encryption" -> {
                            // Generated at the requested modulus size. The size is
                            // still read back off the key rather than assumed, so a
                            // row can never describe something that was not produced.
                            val requestedBits = if (algorithm == "RSA-OAEP-4096") 4096 else 2048
                            publicKeyDer = keystoreManager.generateRSAEncryptionKey(
                                keyId,
                                requestedBits,
                                authDuration
                            )
                            keySizeBits = actualKeySizeBits(publicKeyDer) ?: requestedBits
                        }
                        "secret" -> {
                            keySizeBits = when (algorithm) {
                                "AES-128" -> 128
                                "AES-256" -> 256
                                else -> 256
                            }
                            keystoreManager.generateSymmetricKey(keyId, keySizeBits, authDuration)
                        }
                        "hmac" -> {
                            keySizeBits = if (algorithm.contains("512")) 512 else 256
                            keystoreManager.generateHMACKey(keyId, algorithm)
                        }
                    }

                    val entity = KeyEntity(
                        keyId = keyId,
                        keyType = keyType,
                        algorithm = algorithm,
                        label = label,
                        publicKeyDer = publicKeyDer,
                        keySizeBits = keySizeBits,
                        biometricRequired = biometric,
                        source = "local",
                        createdAt = System.currentTimeMillis()
                    )
                    keyPolicyStore.insertKey(entity)
                }
                Snackbar.make(rootLayout, getString(R.string.key_create_success), Snackbar.LENGTH_SHORT).show()
            } catch (e: Exception) {
                android.util.Log.e("KeyManagement", "Key creation failed", e)
                Snackbar.make(rootLayout, getString(R.string.key_create_error), Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    /**
     * Reads the real key size out of an SPKI-encoded public key.
     *
     * The size stored against a key must describe the key that was produced, not the
     * one the dialog asked for: a request for "RSA-OAEP 4096" is currently satisfied
     * by a 2048-bit modulus, and recording 4096 made the vault claim a strength the
     * key does not have. For RSA this is the modulus bit length, for EC the field
     * size of the curve.
     *
     * @param der The DER/SPKI public key returned by the keystore, or null.
     * @return The key size in bits, or null when [der] is absent or undecodable
     *   (which is the case for Ed25519, whose strength is fixed anyway).
     */
    private fun actualKeySizeBits(der: ByteArray?): Int? {
        if (der == null) return null
        val spec = X509EncodedKeySpec(der)
        // A KeyFactory is selected by key algorithm and SPKI does not name it without
        // decoding the AlgorithmIdentifier, so try the two families this screen can
        // generate and let the other one reject the encoding.
        val publicKey = KEY_FACTORY_ALGORITHMS.firstNotNullOfOrNull { name ->
            runCatching { KeyFactory.getInstance(name).generatePublic(spec) }.getOrNull()
        }
        return when (publicKey) {
            is RSAPublicKey -> publicKey.modulus.bitLength()
            is ECPublicKey -> publicKey.params.curve.field.fieldSize
            else -> {
                android.util.Log.w(
                    "KeyManagementActivity",
                    "Could not read the key size back from the generated public key"
                )
                null
            }
        }
    }

    /**
     * The size a **generation** algorithm nominally implies, used only when the
     * generated key cannot be decoded (Ed25519, or a keystore that returned
     * something unexpected).
     *
     * Only algorithms this screen actually passes to `KeystoreManager` belong here.
     * The `RSA-OAEP-*` labels deliberately do not: they name what the dialog offered,
     * not what was generated, and that gap is the whole reason [actualKeySizeBits]
     * exists.
     */
    private fun nominalKeySizeBits(algorithm: String): Int = when (algorithm) {
        "ES256" -> 256
        "ES384" -> 384
        "RS256" -> 2048
        "RS512" -> 4096
        "Ed25519" -> 256
        else -> 256
    }

    /**
     * Shows delete confirmation dialog.
     *
     * Only reachable for non-system keys: [showKeyContextMenu] adds the Delete item
     * exclusively when `!key.isSystemKey`.
     */
    private fun showDeleteConfirmation(key: KeyEntity) {
        val message = if (key.source == "xkmsd") {
            getString(R.string.remote_key_delete_message, key.label)
        } else {
            getString(R.string.key_delete_message, key.label)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.key_delete_title))
            .setMessage(message)
            .setPositiveButton(getString(R.string.key_delete_confirm)) { _, _ -> deleteKey(key) }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Deletes a key.
     */
    private fun deleteKey(key: KeyEntity) {
        lifecycleScope.launch {
            // With its policy row and grant rows, in one transaction (#193);
            // the material only once the rows of this key row are deleted,
            // in the store's serialisation of its material (#193 r8).
            KeySharingPeers.forgetKey(key.keyId, key.id, keyPolicyStore, material =
                com.automatethethings.xkey.storage.keyMaterialDeleter(this@KeyManagementActivity))
            Snackbar.make(rootLayout, getString(R.string.key_deleted), Snackbar.LENGTH_SHORT).show()
        }
    }

    /**
     * Shows context menu for a key.
     */
    private fun showKeyContextMenu(key: KeyEntity, anchorView: View) {
        PopupMenu(this, anchorView, Gravity.END).apply {
            if (!key.isSystemKey) {
                menu.add(Menu.NONE, MENU_SHARE_SETTINGS, 0, R.string.key_menu_share_settings)
            }
            menu.add(Menu.NONE, MENU_VIEW_DETAILS, 1, R.string.key_menu_view_details)
            if (key.publicKeyDer != null) {
                menu.add(Menu.NONE, MENU_EXPORT_PUBLIC, 2, R.string.key_menu_export_public)
            }
            if (!key.isSystemKey) {
                menu.add(Menu.NONE, MENU_DELETE, 3, R.string.key_menu_delete)
            }

            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    MENU_SHARE_SETTINGS -> {
                        KeySharingBottomSheet.show(supportFragmentManager, key.keyId)
                        true
                    }
                    MENU_VIEW_DETAILS -> {
                        openKeyDetail(key)
                        true
                    }
                    MENU_EXPORT_PUBLIC -> {
                        exportPublicKey(key)
                        true
                    }
                    MENU_DELETE -> {
                        showDeleteConfirmation(key)
                        true
                    }
                    else -> false
                }
            }
            show()
        }
    }

    /**
     * Opens key detail activity.
     */
    private fun openKeyDetail(key: KeyEntity) {
        val intent = Intent(this, KeyDetailActivity::class.java).apply {
            putExtra(KeyDetailActivity.EXTRA_KEY_ID, key.keyId)
        }
        startActivity(intent)
    }

    /**
     * Exports public key to clipboard.
     */
    private fun exportPublicKey(key: KeyEntity) {
        val publicKeyDer = key.publicKeyDer
        if (publicKeyDer == null) {
            Snackbar.make(rootLayout, getString(R.string.key_public_key_unavailable), Snackbar.LENGTH_SHORT).show()
            return
        }

        val base64Key = Base64.encodeToString(publicKeyDer, Base64.NO_WRAP)
        val pemKey = buildString {
            append("-----BEGIN PUBLIC KEY-----\n")
            base64Key.chunked(64).forEach { line ->
                append(line)
                append('\n')
            }
            append("-----END PUBLIC KEY-----")
        }

        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Public Key", pemKey))
        Snackbar.make(rootLayout, getString(R.string.key_public_key_copied), Snackbar.LENGTH_SHORT).show()
    }

    // -------------------------------------------------------------------------
    // Key Type Helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the drawable resource ID for a key type icon.
     */
    private fun getKeyTypeIconRes(keyType: String): Int = when (keyType) {
        "fido2" -> R.drawable.ic_key_fido2
        "tls" -> R.drawable.ic_key_tls
        "ssh" -> R.drawable.ic_key_ssh
        "signing" -> R.drawable.ic_key_signing
        "encryption" -> R.drawable.ic_key_encryption
        "secret" -> R.drawable.ic_key_secret
        "hmac" -> R.drawable.ic_key_hmac
        "ca" -> R.drawable.ic_key_ca
        "attestation" -> R.drawable.ic_key_attestation
        else -> R.drawable.ic_key_modern
    }

    /**
     * Returns the gradient colors for a key type.
     */
    private fun getKeyTypeGradient(keyType: String): Pair<Int, Int> = when (keyType) {
        "fido2" -> Pair(
            ContextCompat.getColor(this, R.color.primary_40),
            ContextCompat.getColor(this, R.color.primary_60)
        )
        "signing" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_40),
            ContextCompat.getColor(this, R.color.tertiary_60)
        )
        "encryption" -> Pair(
            ContextCompat.getColor(this, R.color.security_verified_variant),
            ContextCompat.getColor(this, R.color.security_verified)
        )
        "tls" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_30),
            ContextCompat.getColor(this, R.color.tertiary_50)
        )
        "ssh" -> Pair(
            ContextCompat.getColor(this, R.color.primary_50),
            ContextCompat.getColor(this, R.color.primary_70)
        )
        "secret" -> Pair(
            ContextCompat.getColor(this, R.color.secondary_60),
            ContextCompat.getColor(this, R.color.secondary_70)
        )
        "hmac" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_50),
            ContextCompat.getColor(this, R.color.tertiary_70)
        )
        "ca" -> Pair(
            ContextCompat.getColor(this, R.color.primary_20),
            ContextCompat.getColor(this, R.color.primary_40)
        )
        "attestation" -> Pair(
            ContextCompat.getColor(this, R.color.secondary_50),
            ContextCompat.getColor(this, R.color.secondary_70)
        )
        else -> Pair(
            ContextCompat.getColor(this, R.color.primary_40),
            ContextCompat.getColor(this, R.color.primary_60)
        )
    }

    /**
     * Returns a human-readable display name for a key type.
     */
    private fun getKeyTypeDisplayName(keyType: String): String = when (keyType) {
        "fido2" -> "FIDO2"
        "tls" -> "TLS"
        "ssh" -> "SSH"
        "signing" -> getString(R.string.key_filter_signing)
        "encryption" -> getString(R.string.key_filter_encryption)
        "secret" -> getString(R.string.key_filter_secret)
        "hmac" -> "HMAC"
        "ca" -> getString(R.string.key_filter_ca)
        "attestation" -> getString(R.string.key_filter_attestation)
        else -> keyType.replaceFirstChar { it.uppercase() }
    }

    // -------------------------------------------------------------------------
    // RecyclerView Adapter
    // -------------------------------------------------------------------------

    /**
     * Premium RecyclerView adapter for key cards.
     */
    inner class KeyListAdapter : ListAdapter<KeyEntity, KeyListAdapter.ViewHolder>(KeyDiffCallback()) {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(buildPremiumKeyCard(parent.context))
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }

        /**
         * Builds a premium key card layout.
         */
        private fun buildPremiumKeyCard(context: Context): MaterialCardView {
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

            // Share overlay background circle
            val shareOverlayBg = View(context).apply {
                layoutParams = FrameLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 18),
                    UIHelpers.dpToPxInt(context, 18)
                ).apply { gravity = Gravity.BOTTOM or Gravity.END }
                background = UIHelpers.createRoundedDrawable(
                    ContextCompat.getColor(context, R.color.security_verified),
                    UIHelpers.dpToPx(context, 9f)
                )
                visibility = View.GONE
                tag = "shareOverlayBg"
            }
            iconContainer.addView(shareOverlayBg)

            // Share icon overlay
            val shareOverlay = ImageView(context).apply {
                setImageResource(R.drawable.ic_share_key)
                layoutParams = FrameLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 16)
                ).apply { gravity = Gravity.BOTTOM or Gravity.END; marginStart = 1; topMargin = 1 }
                imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(context, R.color.on_primary)
                )
                visibility = View.GONE
                tag = "shareOverlay"
            }
            iconContainer.addView(shareOverlay)

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

            val labelText = TextView(context).apply {
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                tag = "label"
            }
            infoColumn.addView(labelText)

            // Algorithm and type row
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
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
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
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }
            metaRow.addView(separatorText)

            val typeText = TextView(context).apply {
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                tag = "type"
            }
            metaRow.addView(typeText)
            infoColumn.addView(metaRow)

            // Badges row
            val badgeRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 6)
                }
                tag = "badgeRow"
            }
            infoColumn.addView(badgeRow)

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
            private val iconView: ImageView = itemView.findViewWithTag("icon")
            private val labelView: TextView = itemView.findViewWithTag("label")
            private val algorithmView: TextView = itemView.findViewWithTag("algorithm")
            private val typeView: TextView = itemView.findViewWithTag("type")
            private val badgeRow: LinearLayout = itemView.findViewWithTag("badgeRow")
            private val shareOverlay: ImageView = itemView.findViewWithTag("shareOverlay")
            private val shareOverlayBg: View = itemView.findViewWithTag("shareOverlayBg")

            fun bind(key: KeyEntity) {
                // Set icon with gradient background
                iconView.setImageResource(getKeyTypeIconRes(key.keyType))
                val (gradientStart, gradientEnd) = getKeyTypeGradient(key.keyType)
                iconContainer.background = UIHelpers.createRoundedDrawable(
                    gradientStart,
                    UIHelpers.dpToPx(itemView.context, 24f)
                ).apply {
                    val gradient = GradientDrawable(
                        GradientDrawable.Orientation.TL_BR,
                        intArrayOf(gradientStart, gradientEnd)
                    )
                    gradient.cornerRadius = UIHelpers.dpToPx(itemView.context, 24f)
                    iconContainer.background = gradient
                }

                // Set text fields
                labelView.text = key.label
                algorithmView.text = key.algorithm
                typeView.text = getKeyTypeDisplayName(key.keyType)

                // Build badges
                badgeRow.removeAllViews()

                if (key.strongBoxBacked) {
                    badgeRow.addView(createKeyBadge(
                        getString(R.string.key_badge_strongbox),
                        ContextCompat.getColor(itemView.context, R.color.tertiary),
                        ContextCompat.getColor(itemView.context, R.color.on_tertiary)
                    ))
                }

                if (key.biometricRequired) {
                    badgeRow.addView(createKeyBadge(
                        getString(R.string.key_badge_biometric),
                        ContextCompat.getColor(itemView.context, R.color.secondary),
                        ContextCompat.getColor(itemView.context, R.color.on_secondary)
                    ))
                }

                if (key.source == "xkmsd") {
                    badgeRow.addView(createKeyBadge(
                        getString(R.string.key_badge_remote),
                        ContextCompat.getColor(itemView.context, R.color.primary),
                        ContextCompat.getColor(itemView.context, R.color.on_primary)
                    ))
                }

                if (key.sharingPolicy != SharingPolicyType.PRIVATE) {
                    badgeRow.addView(createKeyBadge(
                        getString(R.string.key_badge_shared),
                        ContextCompat.getColor(itemView.context, R.color.primary_60),
                        ContextCompat.getColor(itemView.context, R.color.on_primary)
                    ))
                }

                if (key.isSystemKey) {
                    badgeRow.addView(createKeyBadge(
                        getString(R.string.key_badge_system),
                        UIHelpers.resolveThemeColor(
                            itemView.context,
                            com.google.android.material.R.attr.colorSurfaceVariant
                        ),
                        UIHelpers.resolveThemeColor(
                            itemView.context,
                            com.google.android.material.R.attr.colorOnSurfaceVariant
                        )
                    ))
                }

                // Share overlay on icon
                val isShared = key.sharingPolicy != SharingPolicyType.PRIVATE
                shareOverlay.visibility = if (isShared) View.VISIBLE else View.GONE
                shareOverlayBg.visibility = if (isShared) View.VISIBLE else View.GONE

                // Click handlers
                itemView.setOnClickListener { openKeyDetail(key) }
                itemView.setOnLongClickListener {
                    showKeyContextMenu(key, itemView)
                    true
                }
            }

            private fun createKeyBadge(text: String, bgColor: Int, textColor: Int): TextView {
                return TextView(itemView.context).apply {
                    this.text = text
                    textSize = 10f
                    setTextColor(textColor)
                    setPadding(
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 3),
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 3)
                    )
                    background = UIHelpers.createRoundedDrawable(
                        bgColor,
                        UIHelpers.dpToPx(context, 10f)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        marginEnd = UIHelpers.dpToPxInt(context, 6)
                    }
                }
            }
        }
    }

    /**
     * DiffUtil callback for efficient list updates.
     */
    class KeyDiffCallback : DiffUtil.ItemCallback<KeyEntity>() {
        override fun areItemsTheSame(oldItem: KeyEntity, newItem: KeyEntity): Boolean {
            return oldItem.keyId == newItem.keyId
        }

        override fun areContentsTheSame(oldItem: KeyEntity, newItem: KeyEntity): Boolean {
            return oldItem == newItem
        }
    }
}

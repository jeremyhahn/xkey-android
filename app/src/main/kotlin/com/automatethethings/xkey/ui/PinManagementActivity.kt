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
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputType
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.automatethethings.xkey.R
import com.automatethethings.xkey.pin.PinException
import com.automatethethings.xkey.pin.PinLockedException
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.pin.PinType
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Activity for managing SO PIN and User PIN lifecycle.
 *
 * Provides a premium programmatic UI (no XML layout) for PIN management
 * following the PKCS#11 security model:
 * - SO PIN (Security Officer) must be set first to initialize the device
 * - User PIN requires SO PIN authentication to provision
 * - SO PIN can reset User PIN lockouts
 * - Both PINs enforce independent lockout counters
 *
 * Features:
 * - Gradient toolbar with back navigation
 * - Hero status card showing SO PIN, User PIN, and initialization status
 * - Lockout status card with countdown timer (visible only during lockout/failed attempts)
 * - Context-sensitive action cards that appear based on current PIN state
 * - PIN entry dialogs with validation
 * - Reactive UI via [PinSettingsRepository.settingsFlow]
 */
class PinManagementActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private lateinit var pinSettingsRepository: PinSettingsRepository
    private lateinit var pinManager: PinManager

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout

    // Hero status card views
    private lateinit var soPinStatusBadge: TextView
    private lateinit var userPinStatusBadge: TextView
    private lateinit var initializedStatusBadge: TextView

    // Lockout card views
    private lateinit var lockoutCard: MaterialCardView
    private lateinit var lockoutTitleText: TextView
    private lateinit var lockoutDetailText: TextView
    private lateinit var lockoutBadge: TextView

    // Action cards container
    private lateinit var actionCardsContainer: LinearLayout

    // Countdown timer for lockout display
    private var lockoutTimer: CountDownTimer? = null

    // Current settings snapshot for action card visibility
    private var currentSettings: PinSettingsData = PinSettingsData()

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        pinSettingsRepository = PinSettingsRepository(this)
        pinManager = PinManager(pinSettingsRepository)

        buildUI()
        setContentView(rootLayout)
        observeSettings()
    }

    override fun onDestroy() {
        super.onDestroy()
        lockoutTimer?.cancel()
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
                this@PinManagementActivity,
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

        val scrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            isFillViewport = true
        }

        val scrollContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                0,
                0,
                0,
                UIHelpers.dpToPxInt(this@PinManagementActivity, 24)
            )
        }

        buildHeroStatusCard(scrollContent)
        buildLockoutCard(scrollContent)
        buildActionCardsContainer(scrollContent)

        scrollView.addView(scrollContent)
        contentLayout.addView(scrollView)
        rootLayout.addView(contentLayout)
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
                UIHelpers.resolveActionBarSize(this@PinManagementActivity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            title = getString(R.string.pin_management_title)
            setTitleTextColor(ContextCompat.getColor(this@PinManagementActivity, R.color.on_primary))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.pin_management_subtitle)
            setTextColor(ContextCompat.getColor(
                this@PinManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 12)
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

    // -------------------------------------------------------------------------
    // Hero Status Card
    // -------------------------------------------------------------------------

    private fun buildHeroStatusCard(parent: LinearLayout) {
        val heroCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@PinManagementActivity, 100)
            isClickable = false
            isFocusable = false
        }

        val gradientStart = ContextCompat.getColor(this, R.color.gradient_security_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_security_end)
        PremiumCardFactory.applyDiagonalGradient(heroCard, gradientStart, gradientEnd)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 20),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 20),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 20),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 20)
            )
        }

        // Title
        val titleText = TextView(this).apply {
            text = getString(R.string.pin_status_title)
            textSize = 20f
            setTextColor(ContextCompat.getColor(this@PinManagementActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PinManagementActivity, 16)
            }
        }
        cardContent.addView(titleText)

        // SO PIN row
        val soPinRow = createStatusRow(getString(R.string.pin_label_so))
        soPinStatusBadge = soPinRow.second
        cardContent.addView(soPinRow.first)

        // User PIN row
        val userPinRow = createStatusRow(getString(R.string.pin_label_user))
        userPinStatusBadge = userPinRow.second
        cardContent.addView(userPinRow.first)

        // Initialized row
        val initializedRow = createStatusRow(getString(R.string.pin_label_initialized))
        initializedStatusBadge = initializedRow.second
        cardContent.addView(initializedRow.first)

        heroCard.addView(cardContent)
        parent.addView(heroCard)
    }

    /**
     * Creates a horizontal status row with a label and badge.
     *
     * @param label The status label text.
     * @return A Pair of the row layout and the badge TextView for dynamic updates.
     */
    private fun createStatusRow(label: String): Pair<LinearLayout, TextView> {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(this).apply {
            text = label
            textSize = 15f
            setTextColor(ContextCompat.getColor(
                this@PinManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.9f) })
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }

        val badge = TextView(this).apply {
            text = getString(R.string.pin_badge_not_set)
            textSize = 12f
            setTextColor(ContextCompat.getColor(this@PinManagementActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 10),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 4),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 10),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                ContextCompat.getColor(this@PinManagementActivity, R.color.security_neutral),
                UIHelpers.dpToPx(this@PinManagementActivity, 12f)
            )
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        row.addView(labelView)
        row.addView(badge)
        return Pair(row, badge)
    }

    // -------------------------------------------------------------------------
    // Lockout Status Card
    // -------------------------------------------------------------------------

    private fun buildLockoutCard(parent: LinearLayout) {
        lockoutCard = PremiumCardFactory.createOutlinedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 8),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
                )
            }
            strokeColor = ContextCompat.getColor(
                this@PinManagementActivity,
                R.color.security_danger
            )
            strokeWidth = UIHelpers.dpToPxInt(this@PinManagementActivity, 1)
            visibility = View.GONE
            isClickable = false
            isFocusable = false
        }

        val lockoutContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16)
            )
        }

        // Header row with title and badge
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        lockoutTitleText = TextView(this).apply {
            text = getString(R.string.pin_lockout_title)
            textSize = 16f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }

        lockoutBadge = TextView(this).apply {
            text = getString(R.string.pin_lockout_badge)
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@PinManagementActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 8),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 3),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 8),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 3)
            )
            background = UIHelpers.createRoundedDrawable(
                ContextCompat.getColor(this@PinManagementActivity, R.color.security_danger),
                UIHelpers.dpToPx(this@PinManagementActivity, 10f)
            )
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
        }

        headerRow.addView(lockoutTitleText)
        headerRow.addView(lockoutBadge)

        lockoutDetailText = TextView(this).apply {
            text = ""
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        lockoutContent.addView(headerRow)
        lockoutContent.addView(lockoutDetailText)
        lockoutCard.addView(lockoutContent)
        parent.addView(lockoutCard)
    }

    // -------------------------------------------------------------------------
    // Action Cards Container
    // -------------------------------------------------------------------------

    private fun buildActionCardsContainer(parent: LinearLayout) {
        // Section header
        val sectionHeader = TextView(this).apply {
            text = getString(R.string.pin_actions_header)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 20),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 20),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
                )
            }
            letterSpacing = 0.05f
        }
        parent.addView(sectionHeader)

        actionCardsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        parent.addView(actionCardsContainer)
    }

    // -------------------------------------------------------------------------
    // Action Card Builder
    // -------------------------------------------------------------------------

    /**
     * Creates a clickable action card with title, description, and optional accent color.
     *
     * @param title The card title.
     * @param description The card description.
     * @param accentColor The left accent stripe color.
     * @param onClick Click handler.
     * @return A configured MaterialCardView.
     */
    private fun createActionCard(
        title: String,
        description: String,
        accentColor: Int,
        onClick: () -> Unit
    ): MaterialCardView {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 4),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@PinManagementActivity, 4)
                )
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Accent stripe
        val accentStripe = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 4),
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(accentColor)
        }
        cardContent.addView(accentStripe)

        // Text content
        val textContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PinManagementActivity, 16)
            )
        }

        val titleView = TextView(this).apply {
            text = title
            textSize = 16f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PinManagementActivity, 4)
            }
        }

        val descriptionView = TextView(this).apply {
            text = description
            textSize = 13f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        textContent.addView(titleView)
        textContent.addView(descriptionView)
        cardContent.addView(textContent)

        // Chevron icon
        val chevron = TextView(this).apply {
            text = "\u203A"
            textSize = 24f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PinManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PinManagementActivity, 40),
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }
        cardContent.addView(chevron)

        card.addView(cardContent)
        return card
    }

    // -------------------------------------------------------------------------
    // Data Observation
    // -------------------------------------------------------------------------

    private fun observeSettings() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                pinSettingsRepository.settingsFlow.collectLatest { settings ->
                    currentSettings = settings
                    updateHeroCard(settings)
                    updateLockoutCard(settings)
                    rebuildActionCards(settings)
                }
            }
        }
    }

    private fun updateHeroCard(settings: PinSettingsData) {
        updateBadge(soPinStatusBadge, settings.soPinSet)
        updateBadge(userPinStatusBadge, settings.userPinSet)
        updateBadge(initializedStatusBadge, settings.soPinSet)
    }

    /**
     * Updates a badge's text, color, and background based on set/not-set state.
     */
    private fun updateBadge(badge: TextView, isSet: Boolean) {
        if (isSet) {
            badge.text = getString(R.string.pin_badge_set)
            badge.background = UIHelpers.createRoundedDrawable(
                ContextCompat.getColor(this, R.color.security_verified),
                UIHelpers.dpToPx(this, 12f)
            )
        } else {
            badge.text = getString(R.string.pin_badge_not_set)
            badge.background = UIHelpers.createRoundedDrawable(
                ContextCompat.getColor(this, R.color.security_neutral),
                UIHelpers.dpToPx(this, 12f)
            )
        }
    }

    private fun updateLockoutCard(settings: PinSettingsData) {
        lockoutTimer?.cancel()
        lockoutTimer = null

        val now = System.currentTimeMillis()
        val soLocked = settings.soPinLockedUntil > now
        val userLocked = settings.userPinLockedUntil > now
        val hasFailedSoAttempts = settings.failedSoPinAttempts > 0
        val hasFailedUserAttempts = settings.failedUserPinAttempts > 0

        val isLocked = soLocked || userLocked
        val hasFailedAttempts = hasFailedSoAttempts || hasFailedUserAttempts

        if (!isLocked && !hasFailedAttempts) {
            lockoutCard.visibility = View.GONE
            return
        }

        lockoutCard.visibility = View.VISIBLE

        // Build detail text
        val lockedSuffix = getString(R.string.pin_lockout_locked_suffix)
        val details = buildString {
            if (hasFailedSoAttempts) {
                append(getString(
                    R.string.pin_lockout_so_attempts,
                    settings.failedSoPinAttempts,
                    settings.maxPinAttempts
                ))
                if (soLocked) append(lockedSuffix)
                append("\n")
            }
            if (hasFailedUserAttempts) {
                append(getString(
                    R.string.pin_lockout_user_attempts,
                    settings.failedUserPinAttempts,
                    settings.maxPinAttempts
                ))
                if (userLocked) append(lockedSuffix)
            }
        }.trim()
        lockoutDetailText.text = details

        // Show/hide lockout badge
        lockoutBadge.visibility = if (isLocked) View.VISIBLE else View.GONE

        // Set card stroke color based on lockout state
        lockoutCard.strokeColor = ContextCompat.getColor(
            this,
            if (isLocked) R.color.security_danger else R.color.secondary
        )

        // Start countdown timer if locked
        if (isLocked) {
            val longestLockout = maxOf(settings.soPinLockedUntil, settings.userPinLockedUntil)
            val remaining = longestLockout - now

            lockoutTimer = object : CountDownTimer(remaining, 1000L) {
                override fun onTick(millisUntilFinished: Long) {
                    val seconds = (millisUntilFinished / 1000).toInt()
                    val minutes = seconds / 60
                    val secs = seconds % 60
                    val timeText = if (minutes > 0) {
                        getString(R.string.pin_lockout_minutes_remaining, minutes, secs)
                    } else {
                        getString(R.string.pin_lockout_seconds_remaining, secs)
                    }

                    val updatedDetails = buildString {
                        if (hasFailedSoAttempts || soLocked) {
                            append(getString(
                                R.string.pin_lockout_so_attempts,
                                settings.failedSoPinAttempts,
                                settings.maxPinAttempts
                            ))
                            if (soLocked) append(lockedSuffix)
                            append("\n")
                        }
                        if (hasFailedUserAttempts || userLocked) {
                            append(getString(
                                R.string.pin_lockout_user_attempts,
                                settings.failedUserPinAttempts,
                                settings.maxPinAttempts
                            ))
                            if (userLocked) append(lockedSuffix)
                            append("\n")
                        }
                        append("\n")
                        append(getString(R.string.pin_lockout_time_remaining, timeText))
                    }.trim()
                    lockoutDetailText.text = updatedDetails
                }

                override fun onFinish() {
                    lockoutBadge.visibility = View.GONE
                    lockoutDetailText.text = getString(R.string.pin_lockout_expired)
                    lockoutCard.strokeColor = ContextCompat.getColor(
                        this@PinManagementActivity,
                        R.color.secondary
                    )
                }
            }.start()
        }
    }

    private fun rebuildActionCards(settings: PinSettingsData) {
        actionCardsContainer.removeAllViews()

        // "Set SO PIN" - only if SO PIN is not set
        if (!settings.soPinSet) {
            actionCardsContainer.addView(
                createActionCard(
                    title = getString(R.string.pin_action_set_so_title),
                    description = getString(R.string.pin_action_set_so_desc),
                    accentColor = ContextCompat.getColor(this, R.color.gradient_primary_start)
                ) {
                    showSetSoPinDialog()
                }
            )
        }

        // "Set User PIN" - only if SO PIN is set and user PIN is not set
        if (settings.soPinSet && !settings.userPinSet) {
            actionCardsContainer.addView(
                createActionCard(
                    title = getString(R.string.pin_action_set_user_title),
                    description = getString(R.string.pin_action_set_user_desc),
                    accentColor = ContextCompat.getColor(this, R.color.security_verified)
                ) {
                    showSetUserPinDialog()
                }
            )
        }

        // "Change SO PIN" - only if SO PIN is set
        if (settings.soPinSet) {
            actionCardsContainer.addView(
                createActionCard(
                    title = getString(R.string.pin_action_change_so_title),
                    description = getString(R.string.pin_action_change_so_desc),
                    accentColor = ContextCompat.getColor(this, R.color.secondary)
                ) {
                    showChangeSoPinDialog()
                }
            )
        }

        // "Change User PIN" - only if user PIN is set
        if (settings.userPinSet) {
            actionCardsContainer.addView(
                createActionCard(
                    title = getString(R.string.pin_action_change_user_title),
                    description = getString(R.string.pin_action_change_user_desc),
                    accentColor = ContextCompat.getColor(this, R.color.secondary)
                ) {
                    showChangeUserPinDialog()
                }
            )
        }

        // "Reset Lockout" - only if user PIN is locked
        val now = System.currentTimeMillis()
        if (settings.userPinLockedUntil > now) {
            actionCardsContainer.addView(
                createActionCard(
                    title = getString(R.string.pin_action_reset_lockout_title),
                    description = getString(R.string.pin_action_reset_lockout_desc),
                    accentColor = ContextCompat.getColor(this, R.color.security_danger)
                ) {
                    showResetLockoutDialog()
                }
            )
        }
    }

    // -------------------------------------------------------------------------
    // PIN Entry Dialogs
    // -------------------------------------------------------------------------

    /**
     * Creates a [TextInputLayout] wrapping a [TextInputEditText] for password input.
     *
     * @param hint The hint text for the input field.
     * @return A Pair of the [TextInputLayout] and [TextInputEditText].
     */
    private fun createPinInputField(hint: String): Pair<TextInputLayout, TextInputEditText> {
        val inputLayout = TextInputLayout(
            this,
            null,
            com.google.android.material.R.attr.textInputOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PinManagementActivity, 8)
            }
            this.hint = hint
            endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
        }

        val editText = TextInputEditText(inputLayout.context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }

        inputLayout.addView(editText)
        return Pair(inputLayout, editText)
    }

    /**
     * Creates the dialog container LinearLayout with standard padding.
     */
    private fun createDialogContainer(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val hPad = UIHelpers.dpToPxInt(this@PinManagementActivity, 24)
            val vPad = UIHelpers.dpToPxInt(this@PinManagementActivity, 16)
            setPadding(hPad, vPad, hPad, 0)
        }
    }

    private fun showSetSoPinDialog() {
        val container = createDialogContainer()

        val (newPinLayout, newPinInput) = createPinInputField(getString(R.string.pin_hint_new_so))
        val (confirmPinLayout, confirmPinInput) =
            createPinInputField(getString(R.string.pin_hint_confirm_so))

        container.addView(newPinLayout)
        container.addView(confirmPinLayout)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_action_set_so_title)
            .setMessage(R.string.pin_dialog_set_so_message)
            .setView(container)
            .setPositiveButton(R.string.pin_button_set) { _, _ ->
                val newPin = newPinInput.text?.toString() ?: ""
                val confirmPin = confirmPinInput.text?.toString() ?: ""

                if (newPin != confirmPin) {
                    showError(getString(R.string.pin_error_mismatch))
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    try {
                        pinManager.setSOPIN(currentSOPIN = null, newSOPIN = newPin)
                        showSuccess(getString(R.string.pin_success_so_set))
                    } catch (e: PinLockedException) {
                        showError(getString(
                            R.string.pin_error_so_locked,
                            e.lockoutStatus.recoverySeconds
                        ))
                    } catch (e: PinException) {
                        showError(e.message ?: getString(R.string.pin_error_operation_failed))
                    } catch (e: IllegalArgumentException) {
                        showError(e.message ?: getString(R.string.pin_error_invalid_length))
                    }
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showSetUserPinDialog() {
        val container = createDialogContainer()

        val (soPinLayout, soPinInput) = createPinInputField(getString(R.string.pin_label_so))
        val (newPinLayout, newPinInput) = createPinInputField(getString(R.string.pin_hint_new_user))
        val (confirmPinLayout, confirmPinInput) =
            createPinInputField(getString(R.string.pin_hint_confirm_user))

        container.addView(soPinLayout)
        container.addView(newPinLayout)
        container.addView(confirmPinLayout)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_action_set_user_title)
            .setMessage(R.string.pin_dialog_set_user_message)
            .setView(container)
            .setPositiveButton(R.string.pin_button_set) { _, _ ->
                val soPin = soPinInput.text?.toString() ?: ""
                val newPin = newPinInput.text?.toString() ?: ""
                val confirmPin = confirmPinInput.text?.toString() ?: ""

                if (newPin != confirmPin) {
                    showError(getString(R.string.pin_error_mismatch))
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    try {
                        pinManager.setUserPIN(soPIN = soPin, newUserPIN = newPin)
                        showSuccess(getString(R.string.pin_success_user_set))
                    } catch (e: PinLockedException) {
                        showError(getString(
                            R.string.pin_error_locked,
                            e.lockoutStatus.recoverySeconds
                        ))
                    } catch (e: PinException) {
                        showError(e.message ?: getString(R.string.pin_error_operation_failed))
                    } catch (e: IllegalArgumentException) {
                        showError(e.message ?: getString(R.string.pin_error_invalid_length))
                    }
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showChangeSoPinDialog() {
        val container = createDialogContainer()

        val (currentPinLayout, currentPinInput) =
            createPinInputField(getString(R.string.pin_hint_current_so))
        val (newPinLayout, newPinInput) = createPinInputField(getString(R.string.pin_hint_new_so))
        val (confirmPinLayout, confirmPinInput) =
            createPinInputField(getString(R.string.pin_hint_confirm_new_so))

        container.addView(currentPinLayout)
        container.addView(newPinLayout)
        container.addView(confirmPinLayout)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_action_change_so_title)
            .setMessage(R.string.pin_dialog_change_so_message)
            .setView(container)
            .setPositiveButton(R.string.pin_button_change) { _, _ ->
                val currentPin = currentPinInput.text?.toString() ?: ""
                val newPin = newPinInput.text?.toString() ?: ""
                val confirmPin = confirmPinInput.text?.toString() ?: ""

                if (newPin != confirmPin) {
                    showError(getString(R.string.pin_error_mismatch))
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    try {
                        pinManager.changeSOPIN(currentSOPIN = currentPin, newSOPIN = newPin)
                        showSuccess(getString(R.string.pin_success_so_changed))
                    } catch (e: PinLockedException) {
                        showError(getString(
                            R.string.pin_error_so_locked,
                            e.lockoutStatus.recoverySeconds
                        ))
                    } catch (e: PinException) {
                        showError(e.message ?: getString(R.string.pin_error_operation_failed))
                    } catch (e: IllegalArgumentException) {
                        showError(e.message ?: getString(R.string.pin_error_invalid_length))
                    }
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showChangeUserPinDialog() {
        val container = createDialogContainer()

        val (currentPinLayout, currentPinInput) =
            createPinInputField(getString(R.string.pin_hint_current_user))
        val (newPinLayout, newPinInput) = createPinInputField(getString(R.string.pin_hint_new_user))
        val (confirmPinLayout, confirmPinInput) =
            createPinInputField(getString(R.string.pin_hint_confirm_new_user))

        container.addView(currentPinLayout)
        container.addView(newPinLayout)
        container.addView(confirmPinLayout)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_action_change_user_title)
            .setMessage(R.string.pin_dialog_change_user_message)
            .setView(container)
            .setPositiveButton(R.string.pin_button_change) { _, _ ->
                val currentPin = currentPinInput.text?.toString() ?: ""
                val newPin = newPinInput.text?.toString() ?: ""
                val confirmPin = confirmPinInput.text?.toString() ?: ""

                if (newPin != confirmPin) {
                    showError(getString(R.string.pin_error_mismatch))
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    try {
                        pinManager.changeUserPIN(
                            currentUserPIN = currentPin,
                            newUserPIN = newPin
                        )
                        showSuccess(getString(R.string.pin_success_user_changed))
                    } catch (e: PinLockedException) {
                        showError(getString(
                            R.string.pin_error_user_locked,
                            e.lockoutStatus.recoverySeconds
                        ))
                    } catch (e: PinException) {
                        showError(e.message ?: getString(R.string.pin_error_operation_failed))
                    } catch (e: IllegalArgumentException) {
                        showError(e.message ?: getString(R.string.pin_error_invalid_length))
                    }
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showResetLockoutDialog() {
        val container = createDialogContainer()

        val (soPinLayout, soPinInput) = createPinInputField(getString(R.string.pin_label_so))
        container.addView(soPinLayout)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_action_reset_lockout_title)
            .setMessage(R.string.pin_dialog_reset_lockout_message)
            .setView(container)
            .setPositiveButton(R.string.pin_button_reset) { _, _ ->
                val soPin = soPinInput.text?.toString() ?: ""

                lifecycleScope.launch {
                    try {
                        pinManager.resetLockout(soPIN = soPin)
                        showSuccess(getString(R.string.pin_success_lockout_reset))
                    } catch (e: PinLockedException) {
                        showError(getString(
                            R.string.pin_error_so_locked,
                            e.lockoutStatus.recoverySeconds
                        ))
                    } catch (e: PinException) {
                        showError(e.message ?: getString(R.string.pin_error_operation_failed))
                    }
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    // -------------------------------------------------------------------------
    // Feedback
    // -------------------------------------------------------------------------

    private fun showSuccess(message: String) {
        Snackbar.make(rootLayout, message, Snackbar.LENGTH_SHORT).show()
    }

    private fun showError(message: String) {
        Snackbar.make(rootLayout, message, Snackbar.LENGTH_LONG).show()
    }
}

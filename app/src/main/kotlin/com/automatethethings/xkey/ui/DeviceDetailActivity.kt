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

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Typeface
import android.os.Bundle
import android.os.IBinder
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.BleClient
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.protocol.AttestationHelper
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.ca.EnrollmentRefusal
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Premium activity for displaying and managing a single paired device.
 *
 * Provides comprehensive device management with a beautiful UI including:
 * - Collapsing hero header with gradient and device icon
 * - Connection status card with real-time indicator
 * - Identity card (IDevID) with certificate details
 * - Attestation card with status and re-attest functionality
 * - Settings card with policy toggles
 * - Danger zone with unpair option
 *
 * The device is identified by its public key hex, passed via [EXTRA_PUBLIC_KEY_HEX].
 */
class DeviceDetailActivity : AppCompatActivity() {

    companion object {
        /** Intent extra key for the device's public key hex string. */
        const val EXTRA_PUBLIC_KEY_HEX = "publicKeyHex"

        /** Grace period presets offered by the spinner. */
        private val GRACE_PERIOD_OPTIONS = listOf(
            "5 minutes" to 5,
            "15 minutes" to 15,
            "30 minutes" to 30,
            "1 hour" to 60,
            "4 hours" to 240,
            "24 hours" to 1440
        )
    }

    private lateinit var repository: PairedDeviceRepository

    /**
     * Where a refused enrollment is read from.
     *
     * A device that was refused is by definition not enrolled, so the refusal
     * does not live on the paired-device record: it is kept beside the
     * enrollment list under the same public key this screen is opened with.
     */
    private lateinit var enrolledDeviceRepository: EnrolledDeviceRepository

    private var publicKeyHex: String = ""
    private var device: PairedDeviceData? = null

    // Coroutine scope for async operations
    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    // Service binding
    private var gattService: XKeyGattService? = null
    private var serviceBound = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? XKeyGattService.LocalBinder
            gattService = localBinder?.getService()
            serviceBound = true
            updateConnectionStatus()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
            serviceBound = false
        }
    }

    // Root layout for snackbar anchoring
    private lateinit var rootLayout: LinearLayout
    private lateinit var scrollView: ScrollView
    private lateinit var contentLayout: LinearLayout

    // Hero header elements
    private lateinit var heroContainer: FrameLayout
    private lateinit var deviceNameText: TextView
    private lateinit var connectionBadge: TextView

    // Connection card elements
    private lateinit var connectionStatusText: TextView
    private lateinit var connectionStatusIndicator: View
    private lateinit var lastConnectedText: TextView
    private lateinit var connectionDurationText: TextView

    /**
     * The whole "Connection Duration" row.
     *
     * The duration is only known while a session is up, and hiding the value
     * alone left its label stranded beside an empty column — which is the state
     * whenever the device is disconnected.
     */
    private lateinit var connectionDurationRow: LinearLayout

    // Identity card elements
    private lateinit var idevidStatusBadge: TextView
    private lateinit var idevidSubjectText: TextView
    private lateinit var idevidExpiresText: TextView
    private lateinit var idevidTrustLevelText: TextView
    private lateinit var idevidFingerprintText: TextView

    // Attestation card elements
    private lateinit var attestationStatusBadge: TextView
    private lateinit var lastAttestedText: TextView
    private lateinit var gracePeriodRemainingText: TextView
    private lateinit var reattestButton: MaterialButton

    /**
     * The refusal rows, and the whole rows rather than their values.
     *
     * Most devices were never refused, and a label with nothing beside it reads
     * as a missing value rather than as "this never happened" — the same reason
     * [connectionDurationRow] is held onto.
     */
    private lateinit var enrollmentRefusedCaseRow: LinearLayout
    private lateinit var enrollmentRefusedCaseText: TextView
    private lateinit var enrollmentRefusedDetailRow: LinearLayout
    private lateinit var enrollmentRefusedDetailText: TextView
    private lateinit var enrollmentRefusedWhenRow: LinearLayout
    private lateinit var enrollmentRefusedWhenText: TextView

    // Settings card elements
    private lateinit var requireKeyUseSwitch: MaterialSwitch
    private lateinit var requireKeyAttestSwitch: MaterialSwitch
    private lateinit var gracePeriodSpinner: Spinner

    /**
     * The grace-period entries currently offered by the spinner.
     *
     * Normally the presets, but a device may store any `Int` — the pairing
     * protocol and other screens are not limited to the six presets. When the
     * stored value is not one of them an "Other" entry is appended so the real
     * value stays visible and survives the next settings change.
     */
    private var gracePeriodOptions: List<Pair<String, Int>> = GRACE_PERIOD_OPTIONS

    // Flag to prevent settings save during initial load
    private var isInitializing = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        repository = PairedDeviceRepository(this)
        enrolledDeviceRepository = EnrolledDeviceRepository(this)
        publicKeyHex = intent.getStringExtra(EXTRA_PUBLIC_KEY_HEX) ?: run {
            finish()
            return
        }

        // Bind to the service for re-attestation functionality
        Intent(this, XKeyGattService::class.java).also { intent ->
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }

        buildPremiumLayout()
        setContentView(scrollView)
    }

    override fun onDestroy() {
        super.onDestroy()
        activityScope.cancel()
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
    }

    override fun onResume() {
        super.onResume()
        loadDevice()
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
    // Layout Construction
    // -------------------------------------------------------------------------

    /**
     * Constructs the premium layout with collapsing hero header and sectioned cards.
     */
    private fun buildPremiumLayout() {
        scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(
                UIHelpers.resolveThemeColor(context, android.R.attr.colorBackground)
            )
        }

        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        buildHeroHeader()
        buildContentArea()

        scrollView.addView(rootLayout)
    }

    /**
     * Creates the collapsing hero header with gradient, icon, and status badge.
     */
    private fun buildHeroHeader() {
        heroContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.dpToPxInt(context, 200)
            )
        }

        // Gradient background
        val primaryColor = UIHelpers.resolveThemeColor(
            this,
            androidx.appcompat.R.attr.colorPrimary
        )
        val primaryContainerColor = UIHelpers.resolveThemeColor(
            this,
            com.google.android.material.R.attr.colorPrimaryContainer
        )
        heroContainer.background = UIHelpers.createDiagonalGradient(
            primaryColor,
            primaryContainerColor,
            0f
        )

        // Toolbar
        val toolbar = Toolbar(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(context)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.device_detail_title)
            setTitleTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary)
            )
            elevation = 0f
        }

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
        }
        toolbar.navigationIcon?.setTint(
            UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnPrimary)
        )
        heroContainer.addView(toolbar)

        // Center content container
        val centerContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER
            }
            gravity = Gravity.CENTER_HORIZONTAL
        }

        // Device icon container
        val iconContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 72),
                UIHelpers.dpToPxInt(context, 72)
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = UIHelpers.dpToPxInt(context, 12)
            }
        }

        // Icon background circle
        val iconBackground = View(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(
                    UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary),
                    0.2f
                ),
                UIHelpers.dpToPx(context, 36f)
            )
        }
        iconContainer.addView(iconBackground)

        // Device icon
        val deviceIcon = ImageView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 40),
                UIHelpers.dpToPxInt(context, 40)
            ).apply {
                gravity = Gravity.CENTER
            }
            setImageResource(android.R.drawable.ic_menu_view)
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary)
            )
        }
        iconContainer.addView(deviceIcon)
        centerContent.addView(iconContainer)

        // Device name
        deviceNameText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = UIHelpers.dpToPxInt(context, 8)
            }
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary)
            )
            gravity = Gravity.CENTER
        }
        centerContent.addView(deviceNameText)

        // Connection status badge
        connectionBadge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            setPadding(
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 6),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 6)
            )
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
        }
        centerContent.addView(connectionBadge)

        heroContainer.addView(centerContent)
        rootLayout.addView(heroContainer)
    }

    /**
     * Creates the scrollable content area with all section cards.
     */
    private fun buildContentArea() {
        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(0, UIHelpers.dpToPxInt(context, 16), 0, UIHelpers.dpToPxInt(context, 32))
        }

        buildConnectionCard()
        buildIdentityCard()
        buildAttestationCard()
        buildSettingsCard()
        buildDangerZoneCard()

        rootLayout.addView(contentLayout)
    }

    /**
     * Creates the connection status card.
     */
    private fun buildConnectionCard() {
        val sectionTitle = createSectionTitle(getString(R.string.device_section_connection))
        contentLayout.addView(sectionTitle)

        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16)
            )
        }

        // Status row with indicator
        val statusRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        connectionStatusIndicator = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 12),
                UIHelpers.dpToPxInt(context, 12)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(context, 12)
            }
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant),
                UIHelpers.dpToPx(context, 6f)
            )
        }
        statusRow.addView(connectionStatusIndicator)

        connectionStatusText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
        }
        statusRow.addView(connectionStatusText)
        cardContent.addView(statusRow)

        // Last connected
        lastConnectedText = createInfoRow(
            cardContent,
            getString(R.string.device_last_connected)
        ).value

        // Connection duration (shown when connected)
        createInfoRow(
            cardContent,
            getString(R.string.device_connection_duration)
        ).also { (row, value) ->
            connectionDurationRow = row
            connectionDurationText = value
        }

        card.addView(cardContent)
        contentLayout.addView(card)
    }

    /**
     * Creates the identity (IDevID) certificate card.
     */
    private fun buildIdentityCard() {
        val sectionTitle = createSectionTitle(getString(R.string.device_section_idevid))
        contentLayout.addView(sectionTitle)

        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16)
            )
        }

        // Status badge row
        val badgeRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 12)
            }
            gravity = Gravity.START
        }

        idevidStatusBadge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(context, 12),
                UIHelpers.dpToPxInt(context, 6),
                UIHelpers.dpToPxInt(context, 12),
                UIHelpers.dpToPxInt(context, 6)
            )
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
        }
        badgeRow.addView(idevidStatusBadge)
        cardContent.addView(badgeRow)

        // Certificate details
        idevidSubjectText = createInfoRow(cardContent, getString(R.string.device_idevid_subject)).value
        idevidExpiresText = createInfoRow(cardContent, getString(R.string.device_idevid_expires)).value
        idevidTrustLevelText =
            createInfoRow(cardContent, getString(R.string.device_idevid_trust_level)).value

        // Fingerprint (copyable)
        val fingerprintRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val fingerprintLabel = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.35f)
            text = getString(R.string.device_idevid_fingerprint)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
        }
        fingerprintRow.addView(fingerprintLabel)

        idevidFingerprintText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.55f)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            typeface = Typeface.MONOSPACE
            textSize = 11f
        }
        fingerprintRow.addView(idevidFingerprintText)

        val copyButton = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 24),
                UIHelpers.dpToPxInt(context, 24)
            ).apply {
                marginStart = UIHelpers.dpToPxInt(context, 8)
            }
            setImageResource(android.R.drawable.ic_menu_save)
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
            )
            setOnClickListener { copyFingerprintToClipboard() }
        }
        fingerprintRow.addView(copyButton)

        cardContent.addView(fingerprintRow)

        card.addView(cardContent)
        contentLayout.addView(card)
    }

    /**
     * Creates the attestation status card with re-attest functionality.
     */
    private fun buildAttestationCard() {
        val sectionTitle = createSectionTitle(getString(R.string.device_section_attestation))
        contentLayout.addView(sectionTitle)

        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16)
            )
        }

        // Status badge row
        val badgeRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 12)
            }
            gravity = Gravity.START
        }

        attestationStatusBadge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(context, 12),
                UIHelpers.dpToPxInt(context, 6),
                UIHelpers.dpToPxInt(context, 12),
                UIHelpers.dpToPxInt(context, 6)
            )
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
        }
        badgeRow.addView(attestationStatusBadge)
        cardContent.addView(badgeRow)

        // Attestation details
        lastAttestedText = createInfoRow(cardContent, getString(R.string.device_last_attested)).value
        gracePeriodRemainingText =
            createInfoRow(cardContent, getString(R.string.device_time_remaining)).value

        // Why enrollment was refused, if it was. The ceremony that issues this
        // device's certificate refuses by name, and until now the name only
        // reached the audit log.
        createInfoRow(cardContent, getString(R.string.device_enrollment_refused_label)).also {
            enrollmentRefusedCaseRow = it.row
            enrollmentRefusedCaseText = it.value
        }
        createInfoRow(cardContent, getString(R.string.device_enrollment_refused_detail)).also {
            enrollmentRefusedDetailRow = it.row
            enrollmentRefusedDetailText = it.value
        }
        createInfoRow(cardContent, getString(R.string.device_enrollment_refused_when)).also {
            enrollmentRefusedWhenRow = it.row
            enrollmentRefusedWhenText = it.value
        }

        // Re-attest button
        reattestButton = MaterialButton(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 16)
            }
            text = getString(R.string.device_reattest_button)
            setBackgroundColor(
                UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
            )
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary)
            )
            cornerRadius = UIHelpers.dpToPxInt(context, 12)
            setOnClickListener { requestReattest() }
        }
        cardContent.addView(reattestButton)

        card.addView(cardContent)
        contentLayout.addView(card)
    }

    /**
     * Creates the settings card with policy toggles and grace period selector.
     */
    private fun buildSettingsCard() {
        val sectionTitle = createSectionTitle(getString(R.string.device_section_settings))
        contentLayout.addView(sectionTitle)

        val card = PremiumCardFactory.createOutlinedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16)
            )
        }

        // Require attestation for key use
        requireKeyUseSwitch = MaterialSwitch(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 16)
            }
            text = getString(R.string.device_require_attest_key_use)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            setOnCheckedChangeListener { _, _ ->
                if (!isInitializing) saveSettings()
            }
        }
        cardContent.addView(requireKeyUseSwitch)

        // Require attestation for key attestation
        requireKeyAttestSwitch = MaterialSwitch(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 16)
            }
            text = getString(R.string.device_require_attest_key_attest)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            setOnCheckedChangeListener { _, _ ->
                if (!isInitializing) saveSettings()
            }
        }
        cardContent.addView(requireKeyAttestSwitch)

        // Grace period selector
        val gracePeriodRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        gracePeriodRow.addView(TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            text = getString(R.string.device_grace_period_label)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
        })

        gracePeriodSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@DeviceDetailActivity,
                android.R.layout.simple_spinner_dropdown_item,
                gracePeriodOptions.map { it.first }
            )
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: AdapterView<*>?,
                    view: View?,
                    position: Int,
                    id: Long
                ) {
                    if (!isInitializing) saveSettings()
                }

                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
        }
        gracePeriodRow.addView(gracePeriodSpinner)
        cardContent.addView(gracePeriodRow)

        card.addView(cardContent)
        contentLayout.addView(card)
    }

    /**
     * Creates the danger zone card with unpair functionality.
     */
    private fun buildDangerZoneCard() {
        val sectionTitle = createSectionTitle(getString(R.string.device_section_danger_zone))
        contentLayout.addView(sectionTitle)

        val card = PremiumCardFactory.createErrorCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 20),
                UIHelpers.dpToPxInt(context, 16)
            )
        }

        // Warning text
        val warningText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(context, 12)
            }
            text = getString(R.string.device_unpair_warning)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnErrorContainer)
            )
        }
        cardContent.addView(warningText)

        // Unpair button
        val unpairButton = MaterialButton(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            text = getString(R.string.device_unpair_button)
            setBackgroundColor(
                UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorError)
            )
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnError)
            )
            cornerRadius = UIHelpers.dpToPxInt(context, 12)
            setOnClickListener { confirmUnpair() }
        }
        cardContent.addView(unpairButton)

        card.addView(cardContent)
        contentLayout.addView(card)
    }

    // -------------------------------------------------------------------------
    // Helper Layout Methods
    // -------------------------------------------------------------------------

    /**
     * Creates a section title TextView.
     */
    private fun createSectionTitle(title: String): TextView {
        return TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 20),
                    UIHelpers.dpToPxInt(context, 20),
                    UIHelpers.dpToPxInt(context, 16),
                    0
                )
            }
        }
    }

    /**
     * A label/value row, as built by [createInfoRow].
     *
     * Callers that need to hide the value need the [row] as well: hiding the
     * value on its own leaves the label behind with nothing beside it.
     */
    private data class InfoRow(val row: LinearLayout, val value: TextView)

    /**
     * Creates an info row with label and value.
     */
    private fun createInfoRow(parent: LinearLayout, label: String): InfoRow {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        row.addView(TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
        })

        val valueText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.END
        }
        row.addView(valueText)

        parent.addView(row)
        return InfoRow(row, valueText)
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    /**
     * Loads device data from the repository and updates the UI.
     */
    private fun loadDevice() {
        isInitializing = true

        device = repository.getDevice(publicKeyHex) ?: run {
            finish()
            return
        }

        val d = device ?: return

        // Hero header
        deviceNameText.text = d.deviceName
        updateConnectionBadge(false) // Will be updated when service connects

        // Connection status
        updateConnectionStatus()

        // IDevID certificate status
        updateIdentityCard(d)

        // Attestation status
        updateAttestationCard(d)
        updateEnrollmentRefusal()

        // Settings
        requireKeyUseSwitch.isChecked = d.requireAttestationForKeyUse
        requireKeyAttestSwitch.isChecked = d.requireAttestationForKeyAttestation

        applyGracePeriod(d.attestationGracePeriodMinutes)

        isInitializing = false
    }

    /**
     * Points the grace-period spinner at [minutes].
     *
     * A stored value outside the presets used to leave the spinner on its first
     * entry, so the very next settings change wrote five minutes over whatever
     * the device actually had. Such a value now gets its own "Other" entry: it
     * is visible, it is selected, and saving preserves it.
     */
    private fun applyGracePeriod(minutes: Int) {
        gracePeriodOptions = gracePeriodOptionsFor(minutes)
        gracePeriodSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            gracePeriodOptions.map { it.first }
        )
        val index = gracePeriodOptions.indexOfFirst { it.second == minutes }
        gracePeriodSpinner.setSelection(if (index >= 0) index else 0)
    }

    /** The presets, plus an "Other" entry when [minutes] is not one of them. */
    private fun gracePeriodOptionsFor(minutes: Int): List<Pair<String, Int>> =
        if (GRACE_PERIOD_OPTIONS.any { it.second == minutes }) {
            GRACE_PERIOD_OPTIONS
        } else {
            GRACE_PERIOD_OPTIONS + (getString(R.string.device_grace_period_other, minutes) to minutes)
        }

    /**
     * Updates the connection status badge in the hero header.
     */
    private fun updateConnectionBadge(isConnected: Boolean) {
        if (isConnected) {
            connectionBadge.text = getString(R.string.device_status_connected)
            connectionBadge.setTextColor(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnTertiary)
            )
            connectionBadge.background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorTertiary),
                UIHelpers.dpToPx(this, 16f)
            )
        } else {
            connectionBadge.text = getString(R.string.device_status_disconnected)
            connectionBadge.setTextColor(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            connectionBadge.background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnPrimary),
                    0.3f
                ),
                UIHelpers.dpToPx(this, 16f)
            )
        }
    }

    /**
     * Updates the connection status card based on service state.
     */
    private fun updateConnectionStatus() {
        val d = device ?: return
        val isConnected = gattService?.getConnectedDevicePublicKeyHex() == publicKeyHex

        // Update hero badge
        updateConnectionBadge(isConnected)

        // Update connection card
        if (isConnected) {
            connectionStatusText.text = getString(R.string.device_connected)
            connectionStatusIndicator.background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorTertiary),
                UIHelpers.dpToPx(this, 6f)
            )
            connectionDurationRow.visibility = View.VISIBLE
            // Duration would need to be tracked
            connectionDurationText.text = getString(R.string.device_na)
        } else {
            connectionStatusText.text = getString(R.string.device_disconnected)
            connectionStatusIndicator.background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant),
                UIHelpers.dpToPx(this, 6f)
            )
            connectionDurationRow.visibility = View.GONE
        }

        // Last connected
        lastConnectedText.text = d.lastConnectedAt?.let {
            formatRelativeTime(it)
        } ?: getString(R.string.device_never_connected)
    }

    /**
     * Updates the identity card with IDevID certificate information.
     */
    private fun updateIdentityCard(d: PairedDeviceData) {
        if (d.hasVerifiedIDevID()) {
            val isExpired = d.isIDevIDExpired()

            if (isExpired) {
                idevidStatusBadge.text = getString(R.string.device_idevid_expired)
                idevidStatusBadge.setTextColor(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnErrorContainer)
                )
                idevidStatusBadge.background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorErrorContainer),
                    UIHelpers.dpToPx(this, 12f)
                )
            } else {
                idevidStatusBadge.text = getString(R.string.device_idevid_verified)
                idevidStatusBadge.setTextColor(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnTertiaryContainer)
                )
                idevidStatusBadge.background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorTertiaryContainer),
                    UIHelpers.dpToPx(this, 12f)
                )
            }

            idevidSubjectText.text = d.idevidSubjectDN ?: getString(R.string.device_unknown)

            val expiryDate = d.idevidNotAfter
            if (expiryDate != null) {
                val formattedDate = formatDate(Date(expiryDate))
                idevidExpiresText.text = formattedDate
                idevidExpiresText.setTextColor(
                    if (isExpired) {
                        UIHelpers.resolveThemeColor(this, androidx.appcompat.R.attr.colorError)
                    } else {
                        UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurface)
                    }
                )
            } else {
                idevidExpiresText.text = getString(R.string.device_na)
            }

            idevidTrustLevelText.text = d.idevidTrustLevel?.uppercase() ?: getString(R.string.device_na)
            idevidFingerprintText.text = d.idevidCertificateDER?.let { computeFingerprint(it) }
                ?: getString(R.string.device_na)
        } else {
            idevidStatusBadge.text = getString(R.string.device_idevid_not_verified)
            idevidStatusBadge.setTextColor(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            idevidStatusBadge.background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorSurfaceVariant),
                UIHelpers.dpToPx(this, 12f)
            )
            idevidSubjectText.text = getString(R.string.device_na)
            idevidExpiresText.text = getString(R.string.device_na)
            idevidTrustLevelText.text = getString(R.string.device_na)
            idevidFingerprintText.text = getString(R.string.device_na)
        }
    }

    /**
     * Updates the attestation card with current status and time remaining.
     */
    private fun updateAttestationCard(d: PairedDeviceData) {
        when {
            d.lastAttestationTime == null -> {
                attestationStatusBadge.text = getString(R.string.device_attest_status_never)
                attestationStatusBadge.setTextColor(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant)
                )
                attestationStatusBadge.background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorSurfaceVariant),
                    UIHelpers.dpToPx(this, 12f)
                )
            }
            isAttestationExpired(d) -> {
                attestationStatusBadge.text = getString(R.string.device_attest_status_expired)
                attestationStatusBadge.setTextColor(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnErrorContainer)
                )
                attestationStatusBadge.background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorErrorContainer),
                    UIHelpers.dpToPx(this, 12f)
                )
            }
            else -> {
                attestationStatusBadge.text = getString(R.string.device_attest_status_current)
                attestationStatusBadge.setTextColor(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnTertiaryContainer)
                )
                attestationStatusBadge.background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorTertiaryContainer),
                    UIHelpers.dpToPx(this, 12f)
                )
            }
        }

        lastAttestedText.text = d.lastAttestationTime?.let {
            formatRelativeTime(it)
        } ?: getString(R.string.key_detail_never)

        gracePeriodRemainingText.text = calculateTimeRemaining(d)
    }

    /**
     * Shows the most recent enrollment refusal for this device, if there is one.
     *
     * The case is what distinguishes a device that answered the credential
     * challenge with the wrong secret from one that never answered at all; the
     * detail names what specifically failed inside that case. Both are shown,
     * because either alone leaves the reader guessing.
     */
    private fun updateEnrollmentRefusal() {
        val record = enrolledDeviceRepository.lastRefusal(publicKeyHex)

        val visibility = if (record == null) View.GONE else View.VISIBLE
        enrollmentRefusedCaseRow.visibility = visibility
        enrollmentRefusedDetailRow.visibility = visibility
        enrollmentRefusedWhenRow.visibility = visibility
        if (record == null) return

        enrollmentRefusedCaseText.text = refusalCaseLabel(record.refusal)
        enrollmentRefusedCaseText.setTextColor(
            UIHelpers.resolveThemeColor(this, androidx.appcompat.R.attr.colorError)
        )
        enrollmentRefusedDetailText.text = record.refusal.detail
        enrollmentRefusedWhenText.text = formatRelativeTime(record.refusedAt)
    }

    /** The label for a refusal case. */
    private fun refusalCaseLabel(refusal: EnrollmentRefusal): String = when (refusal) {
        is EnrollmentRefusal.SigningKeyNotCertified ->
            getString(R.string.device_enrollment_refused_signing_key_not_certified)

        is EnrollmentRefusal.MalformedPackage ->
            getString(R.string.device_enrollment_refused_malformed_package)

        is EnrollmentRefusal.UntrustedEndorsement ->
            getString(R.string.device_enrollment_refused_untrusted_endorsement)

        is EnrollmentRefusal.ActivationMismatch ->
            getString(R.string.device_enrollment_refused_activation_mismatch)

        is EnrollmentRefusal.ActivationUnsupported ->
            getString(R.string.device_enrollment_refused_activation_unsupported)

        is EnrollmentRefusal.QuoteInvalid ->
            getString(R.string.device_enrollment_refused_quote_invalid)
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    /**
     * Copies the IDevID fingerprint to the clipboard.
     */
    private fun copyFingerprintToClipboard() {
        val d = device ?: return
        val fingerprint = d.idevidCertificateDER?.let { computeFingerprint(it) } ?: return

        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("IDevID Fingerprint", fingerprint)
        clipboard.setPrimaryClip(clip)

        Snackbar.make(
            rootLayout,
            getString(R.string.device_fingerprint_copied),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    /**
     * Saves the current settings to the repository.
     */
    private fun saveSettings() {
        val gracePeriod = gracePeriodOptions
            .getOrNull(gracePeriodSpinner.selectedItemPosition)
            ?.second
            ?: return

        repository.updateDeviceSettings(
            publicKeyHex = publicKeyHex,
            requireAttestationForKeyUse = requireKeyUseSwitch.isChecked,
            requireAttestationForKeyAttestation = requireKeyAttestSwitch.isChecked,
            attestationGracePeriodMinutes = gracePeriod
        )
    }

    /**
     * Requests device re-attestation using the appropriate method.
     */
    private fun requestReattest() {
        val service = gattService
        val d = device ?: return

        // Check if already connected via GATT server
        if (service != null) {
            val connectedKey = service.getConnectedDevicePublicKeyHex()
            if (connectedKey == publicKeyHex) {
                performAttestation(service)
                return
            }
        }

        // Try phone-initiated connection if we have BLE address
        val bleAddress = d.bleAddress
        if (bleAddress != null) {
            initiatePhoneConnection(bleAddress, d)
        } else {
            if (service != null) {
                ensureAdvertisingAndShowInstructions(service)
            } else {
                showReattestInstructions()
            }
        }
    }

    /**
     * Initiates a phone-to-laptop connection for re-attestation.
     */
    private fun initiatePhoneConnection(bleAddress: String, deviceData: PairedDeviceData) {
        val snackbar = Snackbar.make(
            rootLayout,
            getString(R.string.device_reattest_connecting),
            Snackbar.LENGTH_INDEFINITE
        )
        snackbar.show()

        launchPhoneInitiatedReattest(snackbar) step@{
                val keyPair = NoiseSession.getStoredStaticKeyPair(this@DeviceDetailActivity)
                if (keyPair == null) {
                    snackbar.dismiss()
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.device_reattest_no_keys),
                        Snackbar.LENGTH_LONG
                    ).show()
                    return@step
                }

                val expectedRemoteKey = try {
                    deviceData.publicKeyHex.chunked(2)
                        .map { it.toInt(16).toByte() }
                        .toByteArray()
                } catch (e: Exception) {
                    null
                }

                // The desktop asks local.attestDevice the moment the handshake
                // completes and drops a session that cannot answer it.
                val client = BleClient(
                    this@DeviceDetailActivity,
                    gattService?.phoneInitiatedRequestHandler(),
                    sasConfirmation()
                )
                val connected = client.connect(
                    address = bleAddress,
                    localStaticKey = keyPair.privateKey,
                    expectedRemoteKey = expectedRemoteKey
                )

                if (!connected) {
                    snackbar.dismiss()
                    gattService?.let { ensureAdvertisingAndShowInstructions(it) }
                        ?: showReattestInstructions()
                    return@step
                }

                snackbar.dismiss()
                Snackbar.make(
                    rootLayout,
                    getString(R.string.device_reattest_in_progress),
                    Snackbar.LENGTH_SHORT
                ).show()

                val attestationHelper = AttestationHelper(this@DeviceDetailActivity)
                val attestResult = attestationHelper.requestLaptopAttestation(client)

                client.disconnect()

                when (attestResult) {
                    is AttestationHelper.AttestationResult.Success -> {
                        // Re-attesting the PEER (`remote.attestDevice`) records its
                        // boot state, but must NOT touch deviceFingerprint — that
                        // field is the phone's own attested-key SPKI bound at
                        // pairing and echoed on reconnect (#93). Omitting it
                        // preserves the reconnect binding.
                        repository.updateDeviceAttestation(
                            publicKeyHex = publicKeyHex,
                            bootHashHex = attestResult.bootHashHex ?: "",
                            securityLevel = attestResult.securityLevel,
                            bootStateVerified = attestResult.bootStateVerified
                        )

                        Snackbar.make(
                            rootLayout,
                            getString(R.string.device_reattest_success),
                            Snackbar.LENGTH_LONG
                        ).show()
                        loadDevice()
                    }
                    is AttestationHelper.AttestationResult.Failure -> {
                        Snackbar.make(
                            rootLayout,
                            getString(R.string.device_reattest_failed) + ": ${attestResult.reason}",
                            Snackbar.LENGTH_LONG
                        ).show()
                    }
                }
        }
    }

    /**
     * Runs one phone-initiated re-attest [step] in this activity's scope, which
     * [onDestroy] cancels. A failure falls back to the advertise-and-wait
     * instructions.
     */
    @VisibleForTesting
    internal fun launchPhoneInitiatedReattest(
        snackbar: Snackbar?,
        step: suspend () -> Unit
    ): Job = activityScope.launch {
        runPhoneInitiatedReattest(
            activityGone = { isFinishing || isDestroyed },
            onFailure = {
                snackbar?.dismiss()
                Snackbar.make(
                    rootLayout,
                    getString(R.string.device_reattest_connection_failed),
                    Snackbar.LENGTH_LONG
                ).show()
                gattService?.let { ensureAdvertisingAndShowInstructions(it) }
                    ?: showReattestInstructions()
            },
            step = step
        )
    }

    /**
     * Asks the user to compare this session's SAS with the code the desktop
     * shows, in the same dialog the sessions the phone accepts use. The session
     * is trusted, and the attestation recorded, only on Allow (#137).
     */
    @VisibleForTesting
    internal fun sasConfirmation(): PairingConfirmationCallback = object : PairingConfirmationCallback {
        override suspend fun onPairingConfirmationRequired(
            deviceName: String,
            publicKeyFingerprint: String
        ): Boolean = false

        override suspend fun onPairingConfirmationRequired(
            deviceName: String,
            publicKeyFingerprint: String,
            shortAuthString: String
        ): Boolean = withContext(Dispatchers.Main) {
            if (isFinishing || isDestroyed) return@withContext false
            suspendCancellableCoroutine { continuation ->
                val dialog = MaterialAlertDialogBuilder(this@DeviceDetailActivity)
                    .setTitle(getString(R.string.pairing_dialog_title))
                    .setMessage(
                        getString(R.string.pairing_dialog_message_sas, deviceName, publicKeyFingerprint, shortAuthString)
                    )
                    .setPositiveButton(getString(R.string.pairing_dialog_allow)) { _, _ ->
                        if (continuation.isActive) continuation.resume(true)
                    }
                    .setNegativeButton(getString(R.string.pairing_dialog_deny)) { _, _ ->
                        if (continuation.isActive) continuation.resume(false)
                    }
                    .setCancelable(false)
                    .show()
                continuation.invokeOnCancellation { dialog.dismiss() }
            }
        }
    }

    /**
     * Performs attestation when already connected.
     */
    private fun performAttestation(service: XKeyGattService) {
        val snackbar = Snackbar.make(
            rootLayout,
            getString(R.string.device_reattest_in_progress),
            Snackbar.LENGTH_INDEFINITE
        )
        snackbar.show()

        activityScope.launch {
            try {
                val success = service.requestDeviceAttestation(publicKeyHex)
                snackbar.dismiss()

                if (success) {
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.device_reattest_success),
                        Snackbar.LENGTH_LONG
                    ).show()
                    loadDevice()
                } else {
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.device_reattest_failed),
                        Snackbar.LENGTH_LONG
                    ).show()
                }
            } catch (e: Exception) {
                snackbar.dismiss()
                Snackbar.make(
                    rootLayout,
                    getString(R.string.device_reattest_failed),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    /**
     * Ensures advertising is active and shows connection instructions.
     */
    private fun ensureAdvertisingAndShowInstructions(service: XKeyGattService) {
        if (!service.isAdvertising()) {
            service.startAdvertising()
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.device_reattest_title))
            .setMessage(getString(R.string.device_reattest_instructions, device?.deviceName ?: "device"))
            .setPositiveButton(getString(R.string.button_ok), null)
            .setNeutralButton(getString(R.string.device_reattest_wait)) { _, _ ->
                waitForConnectionAndAttest(service)
            }
            .show()
    }

    /**
     * Shows instructions when service is unavailable.
     */
    private fun showReattestInstructions() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.device_reattest_title))
            .setMessage(getString(R.string.device_reattest_service_unavailable))
            .setPositiveButton(getString(R.string.button_ok), null)
            .show()
    }

    /**
     * Waits for laptop connection then performs attestation.
     */
    private fun waitForConnectionAndAttest(service: XKeyGattService) {
        val snackbar = Snackbar.make(
            rootLayout,
            getString(R.string.device_reattest_waiting),
            Snackbar.LENGTH_INDEFINITE
        ).setAction(getString(R.string.button_cancel)) {}
        snackbar.show()

        activityScope.launch {
            var timeoutMs = 60_000L
            val checkIntervalMs = 500L

            while (timeoutMs > 0) {
                val connectedKey = service.getConnectedDevicePublicKeyHex()
                if (connectedKey == publicKeyHex) {
                    snackbar.dismiss()
                    performAttestation(service)
                    return@launch
                }

                delay(checkIntervalMs)
                timeoutMs -= checkIntervalMs
            }

            snackbar.dismiss()
            Snackbar.make(
                rootLayout,
                getString(R.string.device_reattest_timeout),
                Snackbar.LENGTH_LONG
            ).show()
        }
    }

    /**
     * Shows confirmation dialog before unpairing.
     */
    private fun confirmUnpair() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.device_unpair_title))
            .setMessage(getString(R.string.device_unpair_message, device?.deviceName ?: ""))
            .setPositiveButton(getString(R.string.device_unpair_confirm)) { _, _ ->
                repository.removeDevice(publicKeyHex)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.device_unpaired),
                    Snackbar.LENGTH_SHORT
                ).show()
                finish()
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------

    /**
     * Checks if device attestation has expired.
     */
    private fun isAttestationExpired(d: PairedDeviceData): Boolean {
        val lastAttest = d.lastAttestationTime ?: return true
        val graceMs = d.attestationGracePeriodMinutes * 60 * 1000L
        return System.currentTimeMillis() - lastAttest > graceMs
    }

    /**
     * Calculates time remaining until attestation expires.
     */
    private fun calculateTimeRemaining(d: PairedDeviceData): String {
        val lastAttest = d.lastAttestationTime ?: return getString(R.string.device_na)
        val graceMs = d.attestationGracePeriodMinutes * 60 * 1000L
        val remaining = graceMs - (System.currentTimeMillis() - lastAttest)

        if (remaining <= 0) return getString(R.string.device_attest_status_expired)

        val hours = TimeUnit.MILLISECONDS.toHours(remaining)
        val minutes = TimeUnit.MILLISECONDS.toMinutes(remaining) % 60
        val seconds = TimeUnit.MILLISECONDS.toSeconds(remaining) % 60

        return when {
            hours > 0 -> getString(R.string.device_time_hms, hours, minutes, seconds)
            minutes > 0 -> getString(R.string.device_time_ms, minutes, seconds)
            else -> getString(R.string.device_time_s, seconds)
        }
    }

    /**
     * Formats a timestamp as relative time.
     */
    private fun formatRelativeTime(timestamp: Long): String {
        val diff = System.currentTimeMillis() - timestamp
        return when {
            diff < 60_000 -> getString(R.string.device_just_now)
            diff < 3600_000 -> getString(R.string.device_minutes_ago, diff / 60_000)
            diff < 86400_000 -> getString(R.string.device_hours_ago, diff / 3600_000)
            else -> SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(timestamp))
        }
    }

    /**
     * Formats a Date to human-readable string.
     */
    private fun formatDate(date: Date): String {
        return SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(date)
    }

    /**
     * Computes truncated SHA-256 fingerprint from DER bytes.
     */
    private fun computeFingerprint(certDER: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(certDER)
        return hash.take(8).joinToString(":") { "%02X".format(it) } + "..."
    }
}

/**
 * Runs a phone-initiated re-attest [step] and hands a failure to [onFailure].
 *
 * [activityGone] reports whether the screen that would show the fallback has
 * been finished or destroyed.
 */
internal suspend fun runPhoneInitiatedReattest(
    activityGone: () -> Boolean,
    onFailure: (Exception) -> Unit,
    step: suspend () -> Unit
) {
    try {
        step()
    } catch (e: Exception) {
        onFailure(e)
    }
}

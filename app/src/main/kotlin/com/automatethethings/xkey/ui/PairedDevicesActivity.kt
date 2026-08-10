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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.IBinder
import android.util.TypedValue
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Premium activity for displaying and managing paired devices.
 *
 * Shows a beautifully designed list of devices that have been paired with this phone
 * for remote key operations. Features:
 * - Gradient header with device count badge
 * - Glass-effect summary card with connection statistics
 * - Premium device cards with trust level indicators
 * - Elegant empty state
 *
 * Tapping a device opens [DeviceDetailActivity] for detailed information
 * and device-specific settings.
 */
class PairedDevicesActivity : AppCompatActivity() {

    private lateinit var repository: PairedDeviceRepository
    private lateinit var adapter: PairedDeviceAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var rootLayout: LinearLayout
    private lateinit var summaryCard: MaterialCardView

    // Summary UI elements
    private lateinit var deviceCountText: TextView
    private lateinit var connectedCountBadge: TextView
    private lateinit var lastConnectionText: TextView

    /**
     * The GATT service, while it is running.
     *
     * The binding deliberately omits `BIND_AUTO_CREATE`: this screen only
     * reports on a session that already exists, and must not bring the
     * foreground service up merely because the user opened the device list.
     * A null service therefore means nothing can be connected.
     */
    private var gattService: XKeyGattService? = null
    private var serviceBindRequested = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            gattService = (binder as? XKeyGattService.LocalBinder)?.getService()
            observeConnectionState()
            updateConnectedBadge(repository.getAllDevices())
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
            updateConnectedBadge(repository.getAllDevices())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        repository = PairedDeviceRepository(this)
        buildPremiumLayout()

        serviceBindRequested = bindService(
            Intent(this, XKeyGattService::class.java),
            serviceConnection,
            0
        )
    }

    override fun onResume() {
        super.onResume()
        loadDevices()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (serviceBindRequested) {
            unbindService(serviceConnection)
            serviceBindRequested = false
        }
    }

    /**
     * Keeps the connected badge in step with the live GATT connection state.
     */
    private fun observeConnectionState() {
        val connectionState = gattService?.getConnectionState() ?: return
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                connectionState.collect {
                    updateConnectedBadge(repository.getAllDevices())
                }
            }
        }
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
     * Constructs the premium layout with gradient header and glass cards.
     */
    private fun buildPremiumLayout() {
        val frameRoot = FrameLayout(this).apply {
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
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        buildPremiumToolbar()
        buildSummaryHeroCard()
        buildDeviceList()
        buildEmptyState()

        frameRoot.addView(rootLayout)
        setContentView(frameRoot)
    }

    /**
     * Creates the premium toolbar with gradient background matching other activities.
     */
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
                UIHelpers.resolveActionBarSize(this@PairedDevicesActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.paired_devices_title)
            setTitleTextColor(ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.settings_paired_devices_description)
            setTextColor(ContextCompat.getColor(
                this@PairedDevicesActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 16),
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 12)
            )
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(subtitle)
        rootLayout.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_chevron_right)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    /**
     * Creates the hero summary card with device statistics, matching the premium
     * pattern used by KeyManagementActivity and OathActivity.
     */
    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@PairedDevicesActivity, 100)
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
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 20),
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 20),
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 20),
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 20)
            )
        }

        // Left section: Icon and count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            gravity = Gravity.CENTER_VERTICAL
        }

        val deviceIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.stat_sys_data_bluetooth)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 64),
                UIHelpers.dpToPxInt(this@PairedDevicesActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@PairedDevicesActivity, 16)
            }
        }

        val textSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        deviceCountText = TextView(this).apply {
            text = "0"
            textSize = 48f
            setTextColor(ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        val devicesLabel = TextView(this).apply {
            text = getString(R.string.paired_devices_label)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(deviceCountText)
        textSection.addView(devicesLabel)
        countSection.addView(deviceIcon)
        countSection.addView(textSection)

        // Right section: connection status badges
        val badgeSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
        }

        connectedCountBadge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(context, 10),
                UIHelpers.dpToPxInt(context, 4),
                UIHelpers.dpToPxInt(context, 10),
                UIHelpers.dpToPxInt(context, 4)
            )
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary))
            background = UIHelpers.createRoundedDrawable(
                ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.2f) },
                UIHelpers.dpToPx(context, 12f)
            )
        }
        badgeSection.addView(connectedCountBadge)

        lastConnectionText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 4)
            }
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@PairedDevicesActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.7f) })
            text = getString(R.string.paired_devices_no_connections)
        }
        badgeSection.addView(lastConnectionText)

        cardContent.addView(countSection)
        cardContent.addView(badgeSection)
        summaryCard.addView(cardContent)
        rootLayout.addView(summaryCard)
    }

    /**
     * Creates the RecyclerView for the device list.
     */
    private fun buildDeviceList() {
        recyclerView = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@PairedDevicesActivity)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            clipToPadding = false
            setPadding(0, 0, 0, UIHelpers.dpToPxInt(context, 16))
        }

        adapter = PairedDeviceAdapter { device ->
            val intent = Intent(this, DeviceDetailActivity::class.java)
            intent.putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, device.publicKeyHex)
            startActivity(intent)
        }
        recyclerView.adapter = adapter
        rootLayout.addView(recyclerView)
    }

    /**
     * Creates the elegant empty state view.
     */
    private fun buildEmptyState() {
        emptyStateContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            gravity = Gravity.CENTER
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(context, 48),
                UIHelpers.dpToPxInt(context, 48),
                UIHelpers.dpToPxInt(context, 48),
                UIHelpers.dpToPxInt(context, 48)
            )
        }

        // Empty state icon container
        val iconContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 120),
                UIHelpers.dpToPxInt(context, 120)
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = UIHelpers.dpToPxInt(context, 24)
            }
        }

        // Circular gradient background
        val circleBackground = View(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(
                    UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorPrimaryContainer),
                    0.5f
                ),
                UIHelpers.dpToPx(context, 60f)
            )
        }
        iconContainer.addView(circleBackground)

        // Icon
        val emptyIcon = ImageView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 56),
                UIHelpers.dpToPxInt(context, 56)
            ).apply {
                gravity = Gravity.CENTER
            }
            setImageResource(android.R.drawable.stat_sys_data_bluetooth)
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimaryContainer)
            )
        }
        iconContainer.addView(emptyIcon)
        emptyStateContainer.addView(iconContainer)

        // Title
        val emptyTitle = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = UIHelpers.dpToPxInt(context, 8)
            }
            text = getString(R.string.paired_devices_empty_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleLarge)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            gravity = Gravity.CENTER
        }
        emptyStateContainer.addView(emptyTitle)

        // Subtitle
        val emptySubtitle = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            text = getString(R.string.paired_devices_empty_subtitle)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            gravity = Gravity.CENTER
        }
        emptyStateContainer.addView(emptySubtitle)

        rootLayout.addView(emptyStateContainer)
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    /**
     * Loads paired devices from the repository and updates the UI.
     */
    private fun loadDevices() {
        val devices = repository.getAllDevices()

        // Update summary card
        deviceCountText.text = devices.size.toString()

        updateConnectedBadge(devices)

        // Update last connection time
        val mostRecentConnection = devices
            .mapNotNull { it.lastConnectedAt }
            .maxOrNull()
        lastConnectionText.text = if (mostRecentConnection != null) {
            getString(R.string.paired_devices_last_connection, formatRelativeTime(mostRecentConnection))
        } else {
            getString(R.string.paired_devices_no_connections)
        }

        // Update list visibility
        if (devices.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyStateContainer.visibility = View.VISIBLE
            animateEmptyState()
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyStateContainer.visibility = View.GONE
            adapter.submitList(devices)
        }
    }

    /**
     * Shows how many of [devices] currently hold a session, hiding the badge
     * when none do.
     *
     * The GATT server serves one peer at a time, so the count is whether the
     * peer it has identified is one of the paired devices. A session that has
     * not completed its identity exchange yet has no public key and is not
     * counted — the badge claims a *paired* device is connected.
     */
    private fun updateConnectedBadge(devices: List<PairedDeviceData>) {
        val connectedKey = gattService?.getConnectedDevicePublicKeyHex()
        val connectedCount = if (connectedKey == null) {
            0
        } else {
            devices.count { it.publicKeyHex.equals(connectedKey, ignoreCase = true) }
        }

        if (connectedCount > 0) {
            connectedCountBadge.visibility = View.VISIBLE
            connectedCountBadge.text =
                getString(R.string.paired_devices_connected_count, connectedCount)
        } else {
            connectedCountBadge.visibility = View.GONE
        }
    }

    /**
     * Animates the empty state elements with a fade-in effect.
     */
    private fun animateEmptyState() {
        emptyStateContainer.alpha = 0f
        emptyStateContainer.translationY = UIHelpers.dpToPx(this, 20f)
        emptyStateContainer.animate()
            .alpha(1f)
            .translationY(0f)
            .setDuration(300)
            .setInterpolator(DecelerateInterpolator())
            .start()
    }

    /**
     * Formats a timestamp as a relative time string.
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
}

/**
 * Premium RecyclerView adapter for displaying paired devices.
 *
 * Each item shows:
 * - Gradient device icon in circular container
 * - Device name (bold)
 * - Fingerprint preview (monospace, truncated)
 * - Last connected timestamp
 * - Connection status indicator
 * - Trust level badge (IDevID verified)
 * - Navigation chevron
 *
 * @param onClick Callback invoked when a device item is tapped.
 */
class PairedDeviceAdapter(
    private val onClick: (PairedDeviceData) -> Unit
) : ListAdapter<PairedDeviceData, PairedDeviceAdapter.ViewHolder>(DiffCallback()) {

    /**
     * ViewHolder for a paired device item.
     */
    class ViewHolder(
        val card: MaterialCardView,
        val iconContainer: FrameLayout,
        val nameText: TextView,
        val fingerprintText: TextView,
        val lastConnectedText: TextView,
        val statusIndicator: View,
        val trustBadge: TextView,
        val attestationBadge: TextView
    ) : RecyclerView.ViewHolder(card)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val context = parent.context

        // Premium elevated card
        val card = PremiumCardFactory.createElevatedCard(context).apply {
            layoutParams = RecyclerView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 6),
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 6)
                )
            }
        }

        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 16)
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        // Icon container with gradient background
        val iconContainer = FrameLayout(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 52),
                UIHelpers.dpToPxInt(context, 52)
            )
        }

        val iconBackground = View(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            val primaryColor = UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorPrimary
            )
            val primaryContainerColor = UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorPrimaryContainer
            )
            background = UIHelpers.createDiagonalGradient(
                primaryColor,
                primaryContainerColor,
                UIHelpers.dpToPx(context, 26f)
            )
        }
        iconContainer.addView(iconBackground)

        val deviceIcon = ImageView(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 28),
                UIHelpers.dpToPxInt(context, 28)
            ).apply {
                gravity = Gravity.CENTER
            }
            setImageResource(android.R.drawable.ic_menu_view)
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnPrimary)
            )
        }
        iconContainer.addView(deviceIcon)

        // Status indicator (green dot overlay)
        val statusIndicator = View(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 14),
                UIHelpers.dpToPxInt(context, 14)
            ).apply {
                gravity = Gravity.BOTTOM or Gravity.END
            }
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorTertiary),
                UIHelpers.dpToPx(context, 7f),
                UIHelpers.dpToPxInt(context, 2),
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorSurface)
            )
            visibility = View.GONE
        }
        iconContainer.addView(statusIndicator)
        row.addView(iconContainer)

        // Info column
        val infoColumn = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = UIHelpers.dpToPxInt(context, 16)
            }
        }

        // Device name
        val nameText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurface)
            )
            maxLines = 1
        }
        infoColumn.addView(nameText)

        // Fingerprint preview
        val fingerprintText = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 2)
            }
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            typeface = Typeface.MONOSPACE
            textSize = 11f
            maxLines = 1
        }
        infoColumn.addView(fingerprintText)

        // Last connected
        val lastConnectedText = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 4)
            }
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
        }
        infoColumn.addView(lastConnectedText)

        // Badge row
        val badgeRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        // Trust badge (IDevID verified)
        val trustBadge = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(context, 8),
                UIHelpers.dpToPxInt(context, 4),
                UIHelpers.dpToPxInt(context, 8),
                UIHelpers.dpToPxInt(context, 4)
            )
            textSize = 10f
            typeface = Typeface.DEFAULT_BOLD
        }
        badgeRow.addView(trustBadge)

        // Attestation badge
        val attestationBadge = TextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginStart = UIHelpers.dpToPxInt(context, 6)
            }
            setPadding(
                UIHelpers.dpToPxInt(context, 8),
                UIHelpers.dpToPxInt(context, 4),
                UIHelpers.dpToPxInt(context, 8),
                UIHelpers.dpToPxInt(context, 4)
            )
            textSize = 10f
            typeface = Typeface.DEFAULT_BOLD
        }
        badgeRow.addView(attestationBadge)

        infoColumn.addView(badgeRow)
        row.addView(infoColumn)

        // Navigation chevron
        val chevron = ImageView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 24),
                UIHelpers.dpToPxInt(context, 24)
            )
            setImageResource(android.R.drawable.ic_media_play)
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            scaleX = 0.8f
            scaleY = 0.8f
        }
        row.addView(chevron)

        card.addView(row)
        return ViewHolder(
            card,
            iconContainer,
            nameText,
            fingerprintText,
            lastConnectedText,
            statusIndicator,
            trustBadge,
            attestationBadge
        )
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val device = getItem(position)
        val context = holder.itemView.context

        // Device name
        holder.nameText.text = device.deviceName

        // Fingerprint preview (truncated with ellipsis)
        val fingerprint = device.deviceFingerprint ?: device.publicKeyHex
        holder.fingerprintText.text = fingerprint.take(24) + "..."

        // Last connected
        holder.lastConnectedText.text = device.lastConnectedAt?.let {
            context.getString(R.string.paired_devices_last_seen, formatRelativeTime(context, it))
        } ?: context.getString(R.string.paired_devices_never_connected)

        // Connection status indicator (would need real connection state)
        holder.statusIndicator.visibility = View.GONE

        // Trust badge (IDevID verified)
        if (device.hasVerifiedIDevID() && !device.isIDevIDExpired()) {
            holder.trustBadge.visibility = View.VISIBLE
            holder.trustBadge.text = context.getString(R.string.paired_devices_trusted)
            holder.trustBadge.setTextColor(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnTertiaryContainer)
            )
            holder.trustBadge.background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorTertiaryContainer),
                UIHelpers.dpToPx(context, 8f)
            )
        } else {
            holder.trustBadge.visibility = View.GONE
        }

        // Attestation status badge
        val (labelResId, bgColor, textColor) = when {
            device.lastAttestationTime == null -> Triple(
                R.string.paired_devices_attestation_never,
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorSurfaceVariant),
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
            isAttestationExpired(device) -> Triple(
                R.string.paired_devices_attestation_expired,
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorErrorContainer),
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnErrorContainer)
            )
            else -> Triple(
                R.string.paired_devices_attestation_verified,
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorTertiaryContainer),
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnTertiaryContainer)
            )
        }

        holder.attestationBadge.text = context.getString(labelResId)
        holder.attestationBadge.setTextColor(textColor)
        holder.attestationBadge.background = UIHelpers.createRoundedDrawable(bgColor, UIHelpers.dpToPx(context, 8f))

        holder.card.setOnClickListener { onClick(device) }
    }

    /**
     * Formats a timestamp as a relative time string.
     */
    private fun formatRelativeTime(context: Context, timestamp: Long): String {
        val diff = System.currentTimeMillis() - timestamp
        return when {
            diff < 60_000 -> context.getString(R.string.device_just_now)
            diff < 3600_000 -> context.getString(R.string.device_minutes_ago, diff / 60_000)
            diff < 86400_000 -> context.getString(R.string.device_hours_ago, diff / 3600_000)
            else -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(timestamp))
        }
    }

    /**
     * Determines if a device's attestation has expired based on its grace period.
     */
    private fun isAttestationExpired(device: PairedDeviceData): Boolean {
        val lastAttest = device.lastAttestationTime ?: return true
        val graceMs = device.attestationGracePeriodMinutes * 60 * 1000L
        return System.currentTimeMillis() - lastAttest > graceMs
    }

    /**
     * DiffUtil callback for efficient list updates.
     */
    class DiffCallback : DiffUtil.ItemCallback<PairedDeviceData>() {
        override fun areItemsTheSame(old: PairedDeviceData, new: PairedDeviceData): Boolean =
            old.publicKeyHex == new.publicKeyHex

        override fun areContentsTheSame(old: PairedDeviceData, new: PairedDeviceData): Boolean =
            old == new
    }
}

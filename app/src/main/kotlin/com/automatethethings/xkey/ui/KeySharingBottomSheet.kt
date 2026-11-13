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

import android.app.Dialog
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.annotation.StringRes
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.FragmentManager
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.remote.DesktopKeyShare
import com.automatethethings.xkey.remote.DesktopSectionRefresh
import com.automatethethings.xkey.remote.DesktopShareDecision
import com.automatethethings.xkey.remote.SharePermissionLedger
import com.automatethethings.xkey.remote.DesktopShareGate
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.remote.loadZeroedOnCancel
import com.automatethethings.xkey.remote.shareSessionChanges
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType as EntitySharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Sharing policy types for per-key access control.
 *
 * Determines how a key can be shared with paired peer devices.
 */
enum class SharingPolicyType {
    /**
     * Key is private to this device only.
     * No paired devices can use this key.
     */
    PRIVATE,

    /**
     * Key is shared with all trusted paired devices.
     * Any device in [PairedDeviceRepository] can use this key.
     */
    ALL_PEERS,

    /**
     * Key is shared with selected devices only.
     * Only devices with explicit [KeySharingPolicy] entries can use this key.
     */
    SELECTED_PEERS
}

/**
 * Bottom sheet dialog for managing per-key sharing settings.
 *
 * Allows users to configure which paired devices can access a specific key
 * with three sharing policy options:
 * - Private: Key cannot be used by any paired devices
 * - All Paired Devices: Any paired device can use this key
 * - Selected Devices: Only specifically chosen devices can use this key
 *
 * When "Selected Devices" is chosen, a list of paired devices is displayed
 * with checkboxes to enable/disable access for each device.
 *
 * Usage:
 * ```kotlin
 * KeySharingBottomSheet.show(supportFragmentManager, keyId)
 * ```
 *
 * The bottom sheet automatically persists changes to the database when
 * the sharing policy or device selections change.
 */
class KeySharingBottomSheet : BottomSheetDialogFragment() {

    private val keyDao by lazy { XKeyDatabase.getInstance(requireContext()).keyDao() }
    private val keySharingPolicyDao by lazy { XKeyDatabase.getInstance(requireContext()).keySharingPolicyDao() }
    private val pairedDeviceRepository by lazy { PairedDeviceRepository(requireContext()) }
    private val sharingPeers by lazy { KeySharingPeers(keyId, keySharingPolicyDao, pairedDeviceRepository) }

    private var keyId: String = ""
    private var keyEntity: KeyEntity? = null

    private lateinit var rootLayout: LinearLayout
    private lateinit var policyRadioGroup: RadioGroup
    private lateinit var peerSelectionContainer: LinearLayout
    private lateinit var peerListLayout: LinearLayout
    private lateinit var emptyPeersText: TextView

    // Paired-desktop section: shown only while a desktop is connected.
    private lateinit var desktopContainer: LinearLayout
    private lateinit var desktopStatusText: TextView
    private lateinit var desktopSendButton: MaterialButton
    private var gattService: XKeyGattService? = null
    private var serviceBound = false

    /** Follows desktop connect, confirm and disconnect while the sheet is started. */
    private var desktopWatch: Job? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            gattService = (binder as? XKeyGattService.LocalBinder)?.getService()
            refreshDesktopSection()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
            refreshDesktopSection()
        }
    }

    /** Set while the stored policy is being reflected into the radio group. */
    private var isApplyingStoredPolicy = false

    private val selectedPolicyFlow = MutableStateFlow(SharingPolicyType.PRIVATE)
    private val peersFlow = MutableStateFlow<List<KeySharingPeers.Peer>>(emptyList())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keyId = arguments?.getString(ARG_KEY_ID) ?: ""
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState) as BottomSheetDialog
        dialog.setOnShowListener { dialogInterface ->
            val bottomSheetDialog = dialogInterface as BottomSheetDialog
            val bottomSheet = bottomSheetDialog.findViewById<View>(
                com.google.android.material.R.id.design_bottom_sheet
            )
            bottomSheet?.let {
                val behavior = BottomSheetBehavior.from(it)
                behavior.state = BottomSheetBehavior.STATE_EXPANDED
                behavior.skipCollapsed = true
            }
        }
        return dialog
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        rootLayout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setBackgroundColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
        }

        buildHeaderSection()
        buildPolicyRadioGroup()
        buildPeerSelectionSection()
        buildDesktopSection()

        // The whole sheet scrolls: on a short screen (landscape, enlarged
        // text) the desktop section below the policies and the peer list
        // would otherwise be cut off with no way to reach its send button.
        return NestedScrollView(requireContext()).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setBackgroundColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
            addView(rootLayout)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        loadKeyData()
        observePolicyChanges()
    }

    override fun onStart() {
        super.onStart()
        // Flags 0: bind only to a running service; with no service there is
        // no desktop, and the sheet stays as it was.
        serviceBound = requireContext().bindService(
            Intent(requireContext(), XKeyGattService::class.java), serviceConnection, 0
        )
        // The section tracks the session while the sheet is open.
        desktopWatch?.cancel()
        desktopWatch = lifecycleScope.launch {
            shareSessionChanges { gattService?.shareSession() }.collect { refreshDesktopSection() }
        }
    }

    override fun onStop() {
        desktopWatch?.cancel()
        desktopWatch = null
        desktopRefresh.cancel()
        if (serviceBound) {
            requireContext().unbindService(serviceConnection)
            serviceBound = false
        }
        gattService = null
        super.onStop()
    }

    // -------------------------------------------------------------------------
    // UI Construction
    // -------------------------------------------------------------------------

    /**
     * Builds the header section with title and key label subtitle.
     */
    private fun buildHeaderSection() {
        val headerContainer = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(24), dpToPxInt(20), dpToPxInt(24), dpToPxInt(8))
        }

        // Title row with icon
        val titleRow = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val icon = ImageView(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPxInt(28), dpToPxInt(28)).apply {
                marginEnd = dpToPxInt(12)
            }
            setImageDrawable(ContextCompat.getDrawable(requireContext(), R.drawable.ic_share_key))
            imageTintList = android.content.res.ColorStateList.valueOf(
                resolveThemeColor(androidx.appcompat.R.attr.colorPrimary)
            )
        }
        titleRow.addView(icon)

        val titleText = TextView(requireContext()).apply {
            text = getString(R.string.sharing_settings_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
        }
        titleRow.addView(titleText)

        headerContainer.addView(titleRow)

        // Subtitle (key label) - will be populated when key loads
        val subtitleText = TextView(requireContext()).apply {
            tag = TAG_SUBTITLE
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(4)
            }
        }
        headerContainer.addView(subtitleText)

        rootLayout.addView(headerContainer)

        // Divider
        val divider = View(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPxInt(1)
            ).apply {
                topMargin = dpToPxInt(12)
            }
            setBackgroundColor(resolveThemeColor(com.google.android.material.R.attr.colorOutlineVariant))
        }
        rootLayout.addView(divider)
    }

    /**
     * Builds the sharing policy radio group section.
     *
     * Uses a custom layout approach where RadioButtons are direct children of
     * the RadioGroup to ensure proper mutual exclusivity. Each option consists
     * of a RadioButton followed by a clickable text container for title/description.
     */
    private fun buildPolicyRadioGroup() {
        val container = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(16), dpToPxInt(16), dpToPxInt(16), dpToPxInt(8))
        }

        policyRadioGroup = RadioGroup(requireContext()).apply {
            orientation = RadioGroup.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Private option
        addPolicyOption(
            id = RADIO_ID_PRIVATE,
            title = getString(R.string.sharing_policy_private),
            description = getString(R.string.sharing_policy_private_desc)
        )

        // All Paired Devices option
        addPolicyOption(
            id = RADIO_ID_ALL_PEERS,
            title = getString(R.string.sharing_policy_all_peers),
            description = getString(R.string.sharing_policy_all_peers_desc)
        )

        // Selected Devices option
        addPolicyOption(
            id = RADIO_ID_SELECTED_PEERS,
            title = getString(R.string.sharing_policy_selected_peers),
            description = getString(R.string.sharing_policy_selected_peers_desc)
        )

        policyRadioGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isApplyingStoredPolicy) return@setOnCheckedChangeListener
            val newPolicy = when (checkedId) {
                RADIO_ID_PRIVATE -> SharingPolicyType.PRIVATE
                RADIO_ID_ALL_PEERS -> SharingPolicyType.ALL_PEERS
                RADIO_ID_SELECTED_PEERS -> SharingPolicyType.SELECTED_PEERS
                else -> SharingPolicyType.PRIVATE
            }
            lifecycleScope.launch {
                selectedPolicyFlow.emit(newPolicy)
                persistSharingPolicy(newPolicy)
            }
        }

        container.addView(policyRadioGroup)
        rootLayout.addView(container)
    }

    /**
     * Adds a policy option to the RadioGroup with proper mutual exclusivity.
     *
     * Creates a RadioButton as a direct child of the RadioGroup (required for
     * mutual exclusivity) with title text inline. A separate description TextView
     * is added below. The entire option area is made clickable to improve UX.
     *
     * @param id Unique view ID for the RadioButton
     * @param title The main title text for the option
     * @param description The secondary description text
     */
    private fun addPolicyOption(id: Int, title: String, description: String) {
        // Create a RadioButton with the title as its text (direct child of RadioGroup)
        val radioButton = RadioButton(requireContext()).apply {
            this.id = id
            text = title
            layoutParams = RadioGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            setPadding(dpToPxInt(8), dpToPxInt(8), dpToPxInt(8), 0)
        }
        policyRadioGroup.addView(radioButton)

        // Add description text below the RadioButton
        val descView = TextView(requireContext()).apply {
            text = description
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            layoutParams = RadioGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                // Align with RadioButton text by adding left margin for radio button width + padding
                marginStart = dpToPxInt(36)
                bottomMargin = dpToPxInt(12)
            }
            // Make description clickable to select the associated RadioButton
            setOnClickListener {
                radioButton.isChecked = true
            }
        }
        policyRadioGroup.addView(descView)
    }

    /**
     * Builds the peer selection section (shown only when SELECTED_PEERS is chosen).
     */
    private fun buildPeerSelectionSection() {
        peerSelectionContainer = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
        }

        // Section header
        val headerText = TextView(requireContext()).apply {
            text = getString(R.string.sharing_select_devices)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginStart = dpToPxInt(20)
                marginEnd = dpToPxInt(20)
                topMargin = dpToPxInt(8)
                bottomMargin = dpToPxInt(8)
            }
        }
        peerSelectionContainer.addView(headerText)

        // Scrollable peer list, nested in the sheet's own scrolling
        val scrollView = NestedScrollView(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPxInt(200)  // Max height for scrollable area
            )
        }

        peerListLayout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(16), 0, dpToPxInt(16), dpToPxInt(16))
        }

        // Empty state text
        emptyPeersText = TextView(requireContext()).apply {
            text = getString(R.string.sharing_no_paired_devices)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(24)
                bottomMargin = dpToPxInt(24)
            }
            visibility = View.GONE
        }
        peerListLayout.addView(emptyPeersText)

        scrollView.addView(peerListLayout)
        peerSelectionContainer.addView(scrollView)
        rootLayout.addView(peerSelectionContainer)
    }

    /**
     * Populates the peer list with paired devices.
     */
    private fun populatePeerList(peers: List<KeySharingPeers.Peer>) {
        // Remove all views except the empty state text
        for (i in peerListLayout.childCount - 1 downTo 0) {
            val child = peerListLayout.getChildAt(i)
            if (child !== emptyPeersText) {
                peerListLayout.removeViewAt(i)
            }
        }

        if (peers.isEmpty()) {
            emptyPeersText.visibility = View.VISIBLE
            return
        }

        emptyPeersText.visibility = View.GONE

        for (peer in peers) {
            peerListLayout.addView(createPeerCard(peer))
        }
    }

    /**
     * Creates a card view for a paired device with checkbox. A peer that is
     * not [KeySharingPeers.Peer.selectable] is dimmed and its checkbox disabled.
     */
    private fun createPeerCard(peer: KeySharingPeers.Peer): MaterialCardView {
        val device = peer.device
        val card = PremiumCardFactory.createCompactCard(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(8)
            }
        }

        val contentLayout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(16), dpToPxInt(12), dpToPxInt(12), dpToPxInt(12))
            gravity = Gravity.CENTER_VERTICAL
        }

        // Device icon
        val deviceIcon = ImageView(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPxInt(32), dpToPxInt(32)).apply {
                marginEnd = dpToPxInt(12)
            }
            setImageDrawable(ContextCompat.getDrawable(requireContext(), R.drawable.ic_peer))
            imageTintList = android.content.res.ColorStateList.valueOf(
                resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant)
            )
        }
        contentLayout.addView(deviceIcon)

        // Text content
        val textLayout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }

        // Device name
        val nameText = TextView(requireContext()).apply {
            text = device.deviceName
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            typeface = Typeface.DEFAULT_BOLD
            maxLines = 1
        }
        textLayout.addView(nameText)

        // Fingerprint (first 16 characters of public key)
        val fingerprint = device.publicKeyHex.take(16).lowercase()
        val fingerprintText = TextView(requireContext()).apply {
            text = fingerprint
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            typeface = Typeface.MONOSPACE
        }
        textLayout.addView(fingerprintText)

        // Last connected timestamp
        val lastConnectedStr = formatLastConnected(device.lastConnectedAt)
        if (lastConnectedStr.isNotEmpty()) {
            val lastConnectedText = TextView(requireContext()).apply {
                text = lastConnectedStr
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelSmall)
                setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            }
            textLayout.addView(lastConnectedText)
        }

        contentLayout.addView(textLayout)

        // Checkbox
        val checkbox = CheckBox(requireContext()).apply {
            isChecked = peer.allowed
            isEnabled = peer.selectable
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnCheckedChangeListener { _, checked ->
                lifecycleScope.launch {
                    updatePeerPolicy(device.publicKeyHex, checked)
                }
            }
        }
        contentLayout.addView(checkbox)

        card.addView(contentLayout)

        if (peer.selectable) {
            // Make entire card clickable to toggle checkbox
            PremiumCardFactory.setCardClickListener(card) {
                checkbox.isChecked = !checkbox.isChecked
            }
        } else {
            card.alpha = DISABLED_ALPHA
        }

        return card
    }

    /**
     * Formats the last connected timestamp for display.
     */
    private fun formatLastConnected(timestamp: Long?): String {
        if (timestamp == null || timestamp == 0L) return ""

        val dateFormat = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())
        return "Last connected: ${dateFormat.format(Date(timestamp))}"
    }

    // -------------------------------------------------------------------------
    // Paired Desktop (remote.sharePublicKey)
    // -------------------------------------------------------------------------

    /**
     * Builds the paired-desktop section: a status line and a send button.
     * Hidden until [refreshDesktopSection] finds a connected desktop.
     */
    private fun buildDesktopSection() {
        desktopContainer = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(20), dpToPxInt(8), dpToPxInt(20), dpToPxInt(16))
            visibility = View.GONE
        }

        val headerText = TextView(requireContext()).apply {
            text = getString(R.string.sharing_desktop_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
        }
        desktopContainer.addView(headerText)

        desktopStatusText = TextView(requireContext()).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(4)
            }
        }
        desktopContainer.addView(desktopStatusText)

        desktopSendButton = MaterialButton(requireContext()).apply {
            text = getString(R.string.sharing_desktop_send_public)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(8)
            }
            visibility = View.GONE
            setOnClickListener { sendToDesktop() }
        }
        desktopContainer.addView(desktopSendButton)

        rootLayout.addView(desktopContainer)
    }

    /** What may leave the phone for this key, as of now. */
    private class ShareInputs(val entity: KeyEntity?, val software: SoftwareKey?, val publicKeyPem: String?)

    /**
     * Reads the key fresh (the policy may just have changed). The caller
     * zeroes [ShareInputs.software]; a cancellation that drops the result at
     * the hand back from the IO dispatcher zeroes it here.
     */
    private suspend fun loadShareInputs(): ShareInputs = loadZeroedOnCancel(
        Dispatchers.IO, zero = { it.software?.material?.fill(0) }
    ) {
        val context = requireContext().applicationContext
        val entity = keyDao.getByKeyId(keyId)
        val software = SoftwareKeyStore(context).get(keyId)
        val pem = if (software == null) runCatching { KeystoreManager(context).getPublicKeyPEM(keyId) }.getOrNull() else null
        ShareInputs(entity, software, pem)
    }

    /** The one share decision, the inbound handlers' rule (a pending revocation refuses SELECTED_PEERS). */
    private val sharePermission by lazy { SharePermission(keySharingPolicyDao, pairedDeviceRepository) }

    /**
     * Shows the desktop section when a desktop is connected, with the send
     * button only for a key [DesktopShareGate] lets go; otherwise the reason.
     * The decision is taken against the peer confirmed on the session the
     * key would go out on, and only the latest refresh may apply one: a
     * disconnect or a new session that overtakes a refresh still deciding
     * always wins.
     */
    private fun refreshDesktopSection() {
        if (!::desktopContainer.isInitialized || !isAdded) return
        desktopRefresh.refresh()
    }

    private val desktopRefresh by lazy {
        DesktopSectionRefresh(
            scope = lifecycleScope,
            currentSession = { if (keyEntity == null) null else gattService?.shareSession() },
            decide = { session ->
                val inputs = loadShareInputs()
                try {
                    DesktopShareGate.decide(
                        inputs.entity, inputs.software, inputs.publicKeyPem,
                        session.peerPublicKeyHex, sharePermission
                    )
                } finally {
                    inputs.software?.material?.fill(0)
                }
            },
            show = show@{ decision ->
                if (!isAdded || !::desktopContainer.isInitialized) return@show
                if (decision == null) {
                    desktopContainer.visibility = View.GONE
                    return@show
                }
                desktopContainer.visibility = View.VISIBLE
                desktopSendButton.visibility =
                    if (decision == DesktopShareDecision.PUBLIC_KEY) View.VISIBLE else View.GONE
                desktopStatusText.text = getString(desktopStatusFor(decision))
            },
            // The key could not be read (e.g. deleted between the store's
            // existence check and its read): nothing can be sent, but the
            // sheet and its policy controls stay usable.
            failed = failed@{ e ->
                if (!isAdded || !::desktopContainer.isInitialized) return@failed
                desktopContainer.visibility = View.VISIBLE
                desktopSendButton.visibility = View.GONE
                desktopStatusText.text =
                    getString(R.string.sharing_desktop_load_failed, e.message ?: e.javaClass.simpleName)
            }
        )
    }

    /**
     * Sends the key's public half to the connected desktop
     * (`remote.sharePublicKey`). The transport, router and confirmed peer all
     * come from one [ShareSession] snapshot, and nothing is sent once that
     * session has been replaced.
     */
    private fun sendToDesktop() {
        val session = gattService?.shareSession() ?: return refreshDesktopSection()
        desktopSendButton.isEnabled = false
        desktopStatusText.text = getString(R.string.sharing_desktop_sending)
        lifecycleScope.launch {
            val message: String? = try {
                // The baseline before any input is read: a delete, replacement
                // or revoke of the key after it refuses the send at admission.
                val baseline = SharePermissionLedger.baseline(keyId)
                val inputs = loadShareInputs()
                // The permission is read again from the store just before the
                // send, so a revoke made while the share was pending wins.
                when (val out = DesktopKeyShare(session).send(
                    baseline, inputs.entity, inputs.software, inputs.publicKeyPem, null, sharePermission,
                    { id -> keyDao.getByKeyId(id) }
                )) {
                    is DesktopKeyShare.Outcome.Sent ->
                        getString(R.string.sharing_desktop_sent, out.result.importId)
                    // Declined, refused, or (null) a changed session: nothing was
                    // imported. A changed session re-reads what the new one allows.
                    else -> desktopOutcomeFor(out)?.let { getString(it) }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                getString(R.string.sharing_desktop_failed, e.message ?: e.javaClass.simpleName)
            }
            if (!isAdded) return@launch
            desktopSendButton.isEnabled = true
            if (message != null) desktopStatusText.text = message else refreshDesktopSection()
        }
    }

    // -------------------------------------------------------------------------
    // Data Loading & Persistence
    // -------------------------------------------------------------------------

    /**
     * Loads key data and initializes the UI state.
     */
    private fun loadKeyData() {
        lifecycleScope.launch {
            val key = keyDao.getByKeyId(keyId)
            if (key == null) {
                dismiss()
                return@launch
            }

            keyEntity = key

            // Update subtitle with key label
            rootLayout.findViewWithTag<TextView>(TAG_SUBTITLE)?.text = key.label

            val currentPolicy = storedPolicyOf(key)
            selectedPolicyFlow.emit(currentPolicy)

            // Reflecting the stored policy must not look like a user choice.
            // check() fires the change listener, which persists — so without this
            // guard, merely opening the sheet writes back whatever was displayed.
            isApplyingStoredPolicy = true
            try {
                when (currentPolicy) {
                    SharingPolicyType.PRIVATE -> policyRadioGroup.check(RADIO_ID_PRIVATE)
                    SharingPolicyType.ALL_PEERS -> policyRadioGroup.check(RADIO_ID_ALL_PEERS)
                    SharingPolicyType.SELECTED_PEERS -> policyRadioGroup.check(RADIO_ID_SELECTED_PEERS)
                }
            } finally {
                isApplyingStoredPolicy = false
            }

            // Load allowed peers
            loadAllowedPeers()
            refreshDesktopSection()
        }
    }

    /**
     * The key's stored sharing policy.
     *
     * `sharing_policy` is the authoritative column; `shareable` is the legacy
     * boolean kept in sync beside it. Deriving the policy from `shareable`
     * cannot distinguish ALL_PEERS from SELECTED_PEERS, and where the two
     * columns have drifted apart it silently demoted the key to PRIVATE.
     */
    private fun storedPolicyOf(key: KeyEntity): SharingPolicyType = when (key.sharingPolicy) {
        EntitySharingPolicyType.PRIVATE -> SharingPolicyType.PRIVATE
        EntitySharingPolicyType.ALL_PEERS -> SharingPolicyType.ALL_PEERS
        EntitySharingPolicyType.SELECTED_PEERS -> SharingPolicyType.SELECTED_PEERS
    }

    /**
     * Follows this key's peer list, re-read on every change to its policy
     * rows, so a deletion made elsewhere reaches the sheet.
     */
    private fun loadAllowedPeers() {
        lifecycleScope.launch {
            sharingPeers.peers().collect { peersFlow.emit(it) }
        }
    }

    /**
     * Observes policy changes and updates the UI accordingly.
     */
    private fun observePolicyChanges() {
        lifecycleScope.launch {
            selectedPolicyFlow.collectLatest { policy ->
                val showPeerSelection = policy == SharingPolicyType.SELECTED_PEERS
                peerSelectionContainer.visibility = if (showPeerSelection) View.VISIBLE else View.GONE

                if (showPeerSelection) {
                    populatePeerList(peersFlow.value)
                }
            }
        }

        lifecycleScope.launch {
            peersFlow.collectLatest { peers ->
                if (selectedPolicyFlow.value == SharingPolicyType.SELECTED_PEERS) {
                    populatePeerList(peers)
                }
            }
        }
    }

    /**
     * Persists the sharing policy to the database.
     *
     * Leaving [SharingPolicyType.SELECTED_PEERS] discards the per-peer grants,
     * for either destination:
     * - [SharingPolicyType.ALL_PEERS] supersedes them — every paired device is
     *   allowed, so a per-peer row can only contradict that later.
     * - [SharingPolicyType.PRIVATE] revokes them. Keeping the rows meant a key
     *   set back to selected peers silently resumed sharing with whoever had
     *   been granted access before, without the user re-confirming anyone.
     *
     * Selecting peers again therefore always starts from nothing.
     */
    private suspend fun persistSharingPolicy(policy: SharingPolicyType) {
        if (keyEntity == null) return

        // Convert local policy type to entity policy type and update both columns
        val entityPolicy = when (policy) {
            SharingPolicyType.PRIVATE -> EntitySharingPolicyType.PRIVATE
            SharingPolicyType.ALL_PEERS -> EntitySharingPolicyType.ALL_PEERS
            SharingPolicyType.SELECTED_PEERS -> EntitySharingPolicyType.SELECTED_PEERS
        }
        // A revoke for any pending desktop share of the key: it is refused at
        // the transport's admission unless admitted before this started.
        SharePermissionLedger.revoking(keyId) {
            keyDao.updateSharingPolicy(keyId, entityPolicy)
            if (policy != SharingPolicyType.SELECTED_PEERS) keySharingPolicyDao.clearPoliciesForKey(keyId)
        }
        refreshDesktopSection()
    }

    /**
     * Updates the sharing policy for a specific peer. The list follows the
     * policy rows; a refused change redraws it from the stored state.
     */
    private suspend fun updatePeerPolicy(peerPublicKeyHex: String, allowed: Boolean) {
        // A withdrawal is a revoke for any pending desktop share of the key:
        // it is refused at the transport's admission unless admitted before
        // this started. A grant goes through the pairing check unwrapped.
        val stands = if (allowed) {
            sharingPeers.setAllowed(peerPublicKeyHex, true)
        } else {
            SharePermissionLedger.revoking(keyId) { sharingPeers.setAllowed(peerPublicKeyHex, false) }
        }
        if (!stands) {
            populatePeerList(peersFlow.value)
        }
        refreshDesktopSection()
    }

    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------

    /**
     * Resolves a theme color attribute to an actual color value.
     */
    private fun resolveThemeColor(attr: Int): Int {
        return UIHelpers.resolveThemeColor(requireContext(), attr)
    }

    /**
     * Converts dp to pixels as an integer.
     */
    private fun dpToPxInt(dp: Int): Int {
        return UIHelpers.dpToPxInt(requireContext(), dp)
    }

    companion object {
        private const val TAG = "KeySharingBottomSheet"
        private const val ARG_KEY_ID = "key_id"
        private const val TAG_SUBTITLE = "subtitle"
        private const val DISABLED_ALPHA = 0.5f

        // Use fixed IDs to avoid issues with generateViewId() in companion object
        private const val RADIO_ID_PRIVATE = 0x7f0a0001
        private const val RADIO_ID_ALL_PEERS = 0x7f0a0002
        private const val RADIO_ID_SELECTED_PEERS = 0x7f0a0003

        /**
         * The status line for a [DesktopShareGate] decision: what will be
         * sent, or why nothing will.
         */
        @StringRes
        internal fun desktopStatusFor(decision: DesktopShareDecision): Int = when (decision) {
            DesktopShareDecision.PUBLIC_KEY -> R.string.sharing_desktop_ready
            DesktopShareDecision.NO_PEER -> R.string.sharing_desktop_no_peer
            DesktopShareDecision.POLICY_DENIED -> R.string.sharing_desktop_policy_denied
            DesktopShareDecision.NOT_FOUND -> R.string.sharing_desktop_no_public_key
            DesktopShareDecision.NOT_EXPORTABLE -> R.string.sharing_desktop_not_exportable
            DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH -> R.string.sharing_desktop_no_wrap_path
        }

        /**
         * The status line after a send: the import id line only when the
         * desktop accepted the key, the refusal when it declined, the gate's
         * reason when nothing was sent, and none when the session changed
         * (the section is re-read for the new session instead).
         */
        @StringRes
        internal fun desktopOutcomeFor(outcome: DesktopKeyShare.Outcome): Int? = when (outcome) {
            is DesktopKeyShare.Outcome.Sent -> R.string.sharing_desktop_sent
            is DesktopKeyShare.Outcome.Declined -> R.string.sharing_desktop_declined
            is DesktopKeyShare.Outcome.Refused -> desktopStatusFor(outcome.decision)
            DesktopKeyShare.Outcome.SessionChanged -> null
        }

        /**
         * Shows the key sharing bottom sheet for a specific key.
         *
         * @param fragmentManager The fragment manager to use for showing the dialog.
         * @param keyId The unique key identifier to manage sharing settings for.
         */
        fun show(fragmentManager: FragmentManager, keyId: String) {
            val fragment = KeySharingBottomSheet().apply {
                arguments = Bundle().apply {
                    putString(ARG_KEY_ID, keyId)
                }
            }
            fragment.show(fragmentManager, TAG)
        }
    }
}

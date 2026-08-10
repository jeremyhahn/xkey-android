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

import android.content.Intent
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.view.MenuItem
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Spinner
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import android.graphics.Typeface
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CAInitResult
import com.automatethethings.xkey.ca.CASubject
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.bootstrap.BootstrapClient
import com.automatethethings.xkey.bootstrap.BootstrapFailedException
import com.automatethethings.xkey.bootstrap.NoMethodsConfiguredException
import com.automatethethings.xkey.credential.CredentialProviderSettingsRepository
import com.automatethethings.xkey.databinding.ActivitySettingsBinding
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.AuthTimeWindow
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.settings.BootstrapSettingsData
import com.automatethethings.xkey.settings.BootstrapSettingsRepository
import com.automatethethings.xkey.settings.BootstrapTimeout
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.media.MediaSigningService
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.snackbar.Snackbar
import java.security.cert.X509Certificate
import kotlinx.coroutines.launch

/**
 * Activity for configuring application settings with premium UI design.
 *
 * Settings are organized into logical groups:
 * - Authentication & Passkeys: Biometric settings, authentication modes, attestation policy
 * - Certificate Authority: CA management, certificate generation, bootstrap methods
 * - Device Trust: TPM-based device identity verification
 * - Connectivity: USB HSM configuration
 *
 * All settings are persisted immediately and take effect for subsequent operations.
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var settingsRepository: BiometricSettingsRepository
    private lateinit var credentialProviderSettingsRepository: CredentialProviderSettingsRepository
    private lateinit var usbHsmSettingsRepository: UsbHsmSettingsRepository
    private lateinit var trustedComputingSettingsRepository: TrustedComputingSettingsRepository
    private lateinit var trustStoreRepository: TrustStoreRepository
    private lateinit var bootstrapSettingsRepository: BootstrapSettingsRepository
    private lateinit var pinSettingsRepository: PinSettingsRepository

    /**
     * Flag to prevent triggering save operations while the UI is populated.
     *
     * Every listener on this screen returns early while this is true, because
     * populating a control programmatically fires its listener and would write
     * back the value that was just read. The flag therefore has to cover the
     * *whole* of a population pass, and two independent passes populate this
     * screen: the one-shot repositories read in [loadOneShotSettings], and every
     * emission of [BiometricSettingsRepository.settingsFlow]. They overlap, so
     * the flag is driven by [populateUi] rather than assigned at either site.
     */
    private var isInitializing: Boolean = true

    /** Population passes currently in flight; see [populateUi]. */
    private var populationPasses: Int = 0

    /** True once the one-shot repositories have been applied to the UI. */
    private var oneShotSettingsLoaded: Boolean = false

    /** True once a biometric settings emission has been applied to the UI. */
    private var biometricSettingsLoaded: Boolean = false

    /** Cached time window values for spinner selection mapping. */
    private val timeWindowValues: List<AuthTimeWindow> = listOf(
        AuthTimeWindow.SECONDS_30,
        AuthTimeWindow.MINUTES_1,
        AuthTimeWindow.MINUTES_2,
        AuthTimeWindow.MINUTES_5,
        AuthTimeWindow.MINUTES_10
    )

    /** Cached bootstrap timeout values for spinner selection mapping. */
    private val bootstrapTimeoutValues: List<BootstrapTimeout> = listOf(
        BootstrapTimeout.SECONDS_10,
        BootstrapTimeout.SECONDS_15,
        BootstrapTimeout.SECONDS_30,
        BootstrapTimeout.SECONDS_60
    )

    // FIDO2 & Passkeys UI elements
    private var switchBiometricAuth: MaterialSwitch? = null
    private var authModeRadioGroup: RadioGroup? = null
    private var radioPerOperation: RadioButton? = null
    private var radioTimeWindow: RadioButton? = null
    private var radioPerSession: RadioButton? = null
    private var authModeContainer: LinearLayout? = null
    private var spinnerTimeWindow: Spinner? = null
    private var timeWindowContainer: LinearLayout? = null
    private var attestationPolicyRadioGroup: RadioGroup? = null
    private var switchCredentialProvider: MaterialSwitch? = null
    private var buttonOpenSystemSettings: Button? = null
    private var credentialProviderContainer: LinearLayout? = null

    // Trusted Computing UI elements
    private var switchTrustedComputing: MaterialSwitch? = null
    private var trustedComputingConditionalContainer: LinearLayout? = null
    private var radioCAxkms: RadioButton? = null
    private var radioCAThisDevice: RadioButton? = null
    private var radioCANone: RadioButton? = null
    private var caUrlContainer: LinearLayout? = null
    private var editTextCAUrl: EditText? = null
    private var buttonFetchCA: Button? = null
    private var switchRequireIDevID: MaterialSwitch? = null
    private var switchFullAttestation: MaterialSwitch? = null
    private var switchTrustNewDevices: MaterialSwitch? = null

    // CA Subject fields
    private var caSubjectContainer: LinearLayout? = null
    private var editTextCAOrg: EditText? = null
    private var editTextCAOU: EditText? = null
    private var editTextCALocality: EditText? = null
    private var editTextCAProvince: EditText? = null
    private var editTextCACountry: EditText? = null
    private var editTextCACN: EditText? = null

    // CA Status/Generation
    private var caGenerationContainer: LinearLayout? = null
    private var caStatusContainer: LinearLayout? = null
    private var rootCAStatusText: TextView? = null
    private var intermediateCAStatusText: TextView? = null
    private var buttonGenerateRoot: Button? = null
    private var buttonGenerateIntermediate: Button? = null
    private var platformCARadioGroup: RadioGroup? = null

    private lateinit var androidCA: AndroidCA

    // Native USB UI elements
    private var switchUsbNative: MaterialSwitch? = null
    private var switchTcpHsm: MaterialSwitch? = null

    // Bootstrap Configuration UI elements
    private var bootstrapMethodsContainer: LinearLayout? = null
    private var switchAutoBootstrap: MaterialSwitch? = null
    private var checkboxDane: CheckBox? = null
    private var daneConfigContainer: LinearLayout? = null
    private var editTextDaneServerUrl: EditText? = null
    private var editTextDaneDnsServer: EditText? = null
    private var switchDaneDot: MaterialSwitch? = null
    private var switchDaneDnssec: MaterialSwitch? = null
    private var checkboxNoise: CheckBox? = null
    private var noiseConfigContainer: LinearLayout? = null
    private var editTextNoiseServerAddress: EditText? = null
    private var editTextNoiseStaticKey: EditText? = null
    private var checkboxSpki: CheckBox? = null
    private var spkiConfigContainer: LinearLayout? = null
    private var editTextSpkiServerUrl: EditText? = null
    private var editTextSpkiPinSha256: EditText? = null
    private var checkboxDirect: CheckBox? = null
    private var directConfigContainer: LinearLayout? = null
    private var editTextDirectServerUrl: EditText? = null
    private var spinnerBootstrapTimeout: Spinner? = null

    // PIN Management UI elements
    private var soPinStatusText: TextView? = null
    private var userPinStatusText: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        settingsRepository = BiometricSettingsRepository(this)
        credentialProviderSettingsRepository = CredentialProviderSettingsRepository(this)
        usbHsmSettingsRepository = UsbHsmSettingsRepository(this)
        trustedComputingSettingsRepository = TrustedComputingSettingsRepository(this)
        trustStoreRepository = TrustStoreRepository(this)
        bootstrapSettingsRepository = BootstrapSettingsRepository(this)
        pinSettingsRepository = PinSettingsRepository(this)
        androidCA = AndroidCA(this)
        androidCA.certificateDao = XKeyDatabase.getInstance(this).certificateDao()

        setupActionBar()
        buildSettingsUI()
        loadSettings()
    }

    /**
     * Configures the action bar with back navigation support.
     */
    private fun setupActionBar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            title = getString(R.string.settings_title)
        }
    }

    /**
     * Builds the complete settings UI with premium styling and logical grouping.
     *
     * Settings are organized into 4 sections:
     * 1. Authentication & Passkeys - Biometric, auth modes, credential provider
     * 2. Certificate Authority - CA config, certificate generation, bootstrap methods
     * 3. Device Trust - Trusted Computing toggles, trust store
     * 4. Connectivity - USB HSM
     */
    private fun buildSettingsUI() {
        val scrollView = binding.root.getChildAt(2) as? androidx.core.widget.NestedScrollView
            ?: return
        val rootLinearLayout = scrollView.getChildAt(0) as? LinearLayout ?: return

        // The XML layout still declares an older, superseded copy of the
        // authentication cards. They are detached rather than merely hidden: a
        // GONE view is still in the hierarchy, so those duplicates keep a second
        // switch titled "Require Biometric Authentication", a second
        // "Per operation" radio and a second credential-provider switch in the
        // tree — none of which is wired to anything. Anything walking the tree
        // by label (accessibility services, automation) reaches the dead copy
        // first, because the XML cards precede the programmatic ones.
        detachFromParent(binding.cardBiometricRequired)
        detachFromParent(binding.cardAuthMode)
        detachFromParent(binding.cardTimeWindow)
        detachFromParent(binding.cardSecurityInfo)
        detachFromParent(binding.cardCredentialProvider)

        // Build all section cards
        buildAuthPasskeysSection(rootLinearLayout)
        buildCertificateAuthoritySection(rootLinearLayout)
        buildDeviceTrustSection(rootLinearLayout)
        buildMediaSigningSection(rootLinearLayout)
        buildConnectivitySection(rootLinearLayout)
        buildPinManagementSection(rootLinearLayout)
    }

    /** Removes [view] from its parent, if it still has one. */
    private fun detachFromParent(view: View) {
        (view.parent as? ViewGroup)?.removeView(view)
    }

    // -------------------------------------------------------------------------
    // Authentication & Passkeys Section
    // -------------------------------------------------------------------------

    /**
     * Builds the Authentication & Passkeys settings section with gradient header.
     */
    private fun buildAuthPasskeysSection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(6))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_fingerprint,
            title = getString(R.string.settings_section_auth),
            description = getString(R.string.settings_section_auth_desc)
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // Explanation
        contentPadding.addView(createExplanationText(getString(R.string.explain_biometric_auth)))

        // Biometric Authentication toggle
        contentPadding.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_biometric_required_title),
            description = getString(R.string.settings_biometric_required_description)
        ).also { (row, switch) ->
            switchBiometricAuth = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                updateAuthModeVisibility(isChecked)
                lifecycleScope.launch {
                    val policy = if (isChecked) {
                        UserVerificationPolicy.REQUIRED
                    } else {
                        UserVerificationPolicy.DISABLED
                    }
                    settingsRepository.updateUserVerificationPolicy(policy)
                }
            }
        }.first)

        // Authentication Mode (conditional)
        val authModeSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(16), 0, 0)
        }
        authModeContainer = authModeSection

        authModeSection.addView(createSubsectionLabel("Authentication Mode"))

        val radioGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        authModeRadioGroup = radioGroup

        val perOpRadio = createRadioOption(
            text = getString(R.string.settings_auth_mode_per_operation),
            description = getString(R.string.settings_auth_mode_per_operation_description),
            isChecked = true
        )
        radioPerOperation = perOpRadio
        radioGroup.addView(perOpRadio)

        val timeWindowRadio = createRadioOption(
            text = getString(R.string.settings_auth_mode_time_window),
            description = getString(R.string.settings_auth_mode_time_window_description)
        )
        radioTimeWindow = timeWindowRadio
        radioGroup.addView(timeWindowRadio)

        val perSessionRadio = createRadioOption(
            text = getString(R.string.settings_auth_mode_per_session),
            description = getString(R.string.settings_auth_mode_per_session_description)
        )
        radioPerSession = perSessionRadio
        radioGroup.addView(perSessionRadio)

        radioGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isInitializing) return@setOnCheckedChangeListener
            val authMode = when (checkedId) {
                radioPerOperation?.id -> BiometricAuthMode.PER_OPERATION
                radioTimeWindow?.id -> BiometricAuthMode.TIME_WINDOW
                radioPerSession?.id -> BiometricAuthMode.PER_SESSION
                else -> BiometricAuthMode.PER_OPERATION
            }
            updateTimeWindowVisibility(authMode)
            lifecycleScope.launch {
                settingsRepository.updateAuthMode(authMode)
            }
        }

        authModeSection.addView(radioGroup)

        // Time Window Duration (conditional)
        val timeWindowSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(12), 0, 0)
        }
        timeWindowContainer = timeWindowSection

        timeWindowSection.addView(createSubsectionLabel(getString(R.string.settings_time_window_title)))
        timeWindowSection.addView(TextView(this).apply {
            text = getString(R.string.settings_time_window_description)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
        })

        val timeSpinner = Spinner(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(8) }
            background = ContextCompat.getDrawable(this@SettingsActivity, R.drawable.spinner_background)
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }
        val timeAdapter = ArrayAdapter.createFromResource(
            this,
            R.array.time_window_options,
            android.R.layout.simple_spinner_item
        )
        timeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        timeSpinner.adapter = timeAdapter
        spinnerTimeWindow = timeSpinner

        timeSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (isInitializing) return
                val selectedTimeWindow = timeWindowValues.getOrNull(position) ?: AuthTimeWindow.MINUTES_2
                lifecycleScope.launch {
                    settingsRepository.updateTimeWindow(selectedTimeWindow)
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        timeWindowSection.addView(timeSpinner)
        authModeSection.addView(timeWindowSection)
        contentPadding.addView(authModeSection)

        // Divider
        contentPadding.addView(createDivider())

        // Attestation Authentication Policy
        contentPadding.addView(createSubsectionLabel(getString(R.string.settings_attestation_policy_title)))
        contentPadding.addView(createExplanationText(getString(R.string.explain_attestation_policy)))
        contentPadding.addView(TextView(this).apply {
            text = getString(R.string.settings_attestation_policy_description)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            setPadding(0, 0, 0, dp(8))
        })

        val attestRadioGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
        }
        attestationPolicyRadioGroup = attestRadioGroup

        val alwaysRadio = createRadioOption(
            text = getString(R.string.settings_attestation_policy_always),
            description = getString(R.string.settings_attestation_policy_always_desc),
            isChecked = true
        )
        attestRadioGroup.addView(alwaysRadio)

        val pairedSkipRadio = createRadioOption(
            text = getString(R.string.settings_attestation_policy_paired_skip),
            description = getString(R.string.settings_attestation_policy_paired_skip_desc)
        )
        attestRadioGroup.addView(pairedSkipRadio)

        val neverRadio = createRadioOption(
            text = getString(R.string.settings_attestation_policy_never),
            description = getString(R.string.settings_attestation_policy_never_desc)
        )
        attestRadioGroup.addView(neverRadio)

        attestRadioGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isInitializing) return@setOnCheckedChangeListener
            val policy = when (checkedId) {
                alwaysRadio.id -> AttestationBiometricPolicy.ALWAYS
                pairedSkipRadio.id -> AttestationBiometricPolicy.PAIRED_DEVICES_SKIP
                neverRadio.id -> AttestationBiometricPolicy.NEVER
                else -> AttestationBiometricPolicy.ALWAYS
            }
            lifecycleScope.launch {
                settingsRepository.updateAttestationBiometricPolicy(policy)
            }
        }

        contentPadding.addView(attestRadioGroup)

        // Credential Provider (Android 14+)
        if (credentialProviderSettingsRepository.isFeatureAvailable()) {
            contentPadding.addView(createDivider())

            val credProviderSection = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
            }
            credentialProviderContainer = credProviderSection

            credProviderSection.addView(createExplanationText(getString(R.string.explain_credential_provider)))
            credProviderSection.addView(createSettingRowWithSwitch(
                title = getString(R.string.settings_credential_provider_title),
                description = getString(R.string.settings_credential_provider_description)
            ).also { (_, switch) ->
                switchCredentialProvider = switch
                switch.setOnCheckedChangeListener { _, isChecked ->
                    if (isInitializing) return@setOnCheckedChangeListener
                    lifecycleScope.launch {
                        credentialProviderSettingsRepository.setEnabled(isChecked)
                    }
                    buttonOpenSystemSettings?.visibility = if (isChecked) View.VISIBLE else View.GONE
                    if (isChecked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        credentialProviderSettingsRepository.openSystemCredentialSettings()
                    }
                }
            }.first)

            val systemSettingsButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = getString(R.string.settings_credential_provider_system_settings)
                visibility = View.GONE
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { topMargin = dp(8) }
                setOnClickListener {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        credentialProviderSettingsRepository.openSystemCredentialSettings()
                    }
                }
            }
            buttonOpenSystemSettings = systemSettingsButton
            credProviderSection.addView(systemSettingsButton)

            contentPadding.addView(credProviderSection)
        }

        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)
    }

    // -------------------------------------------------------------------------
    // Certificate Authority Section
    // -------------------------------------------------------------------------

    /**
     * Builds the Certificate Authority settings section.
     * Contains CA configuration, certificate generation, and bootstrap methods.
     */
    private fun buildCertificateAuthoritySection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(6))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_shield,
            title = getString(R.string.settings_section_ca),
            description = getString(R.string.settings_section_ca_desc)
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // Who signs device identity certificates. Three answers, so a radio
        // group rather than the switch this used to be: a boolean could say
        // "this phone" or "not this phone", never "the xkms server".
        contentPadding.addView(createSubsectionLabel(getString(R.string.settings_ca_source_title)))
        val caSourceGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        radioCAxkms = createRadioOption(
            text = getString(R.string.settings_ca_source_xkms),
            description = getString(R.string.settings_ca_source_xkms_desc)
        ).also { caSourceGroup.addView(it) }
        radioCAThisDevice = createRadioOption(
            text = getString(R.string.settings_ca_source_this_device),
            description = getString(R.string.settings_ca_source_this_device_desc)
        ).also { caSourceGroup.addView(it) }
        radioCANone = createRadioOption(
            text = getString(R.string.settings_ca_source_none),
            description = getString(R.string.settings_ca_source_none_desc),
            isChecked = true
        ).also { caSourceGroup.addView(it) }

        caSourceGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isInitializing) return@setOnCheckedChangeListener
            val source = when (checkedId) {
                radioCAxkms?.id -> CertificateAuthoritySource.XKMS
                radioCAThisDevice?.id -> CertificateAuthoritySource.THIS_DEVICE
                else -> CertificateAuthoritySource.NONE
            }
            applyCASourceVisibility(source)
            lifecycleScope.launch {
                trustedComputingSettingsRepository.updateCASource(source)
            }
        }
        contentPadding.addView(caSourceGroup)
        contentPadding.addView(createExplanationText(getString(R.string.explain_act_as_ca)))

        // CA URL container (shown when NOT acting as CA)
        val urlContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(12), 0, 0)
        }
        caUrlContainer = urlContainer

        urlContainer.addView(createSubsectionLabel(getString(R.string.settings_trusted_computing_ca_url)))
        urlContainer.addView(createExplanationText(getString(R.string.ca_url_description)))

        val caUrlEdit = EditText(this).apply {
            hint = getString(R.string.settings_trusted_computing_ca_url_hint)
            inputType = android.text.InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            // Every other text field on this screen saves on focus loss. This
            // one used to be persisted only as a side effect of "Fetch CA
            // Bundle", so a user who typed a URL and left the screen lost it.
            setOnFocusChangeListener { _, hasFocus ->
                if (!hasFocus && !isInitializing) saveCurrentCAServerUrl()
            }
        }
        editTextCAUrl = caUrlEdit
        urlContainer.addView(caUrlEdit)

        val fetchButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.settings_trusted_computing_fetch_ca)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(8) }
        }
        buttonFetchCA = fetchButton
        setupFetchCAButtonListener(fetchButton, card)
        urlContainer.addView(fetchButton)

        contentPadding.addView(urlContainer)

        // ---- CA Subject Configuration (shown when acting as CA) ----
        val subjectContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(12), 0, 0)
        }
        caSubjectContainer = subjectContainer

        subjectContainer.addView(createSubsectionLabel(getString(R.string.ca_subject_title)))
        subjectContainer.addView(createExplanationText(getString(R.string.ca_subject_explanation)))

        editTextCAOrg = createCASubjectField(getString(R.string.ca_subject_org), getString(R.string.ca_subject_org_hint))
        subjectContainer.addView(editTextCAOrg!!)

        editTextCAOU = createCASubjectField(getString(R.string.ca_subject_ou), getString(R.string.ca_subject_ou_hint))
        subjectContainer.addView(editTextCAOU!!)

        editTextCALocality = createCASubjectField(getString(R.string.ca_subject_locality), getString(R.string.ca_subject_locality_hint))
        subjectContainer.addView(editTextCALocality!!)

        editTextCAProvince = createCASubjectField(getString(R.string.ca_subject_province), getString(R.string.ca_subject_province_hint))
        subjectContainer.addView(editTextCAProvince!!)

        editTextCACountry = createCASubjectField(getString(R.string.ca_subject_country), getString(R.string.ca_subject_country_hint))
        subjectContainer.addView(editTextCACountry!!)

        editTextCACN = createCASubjectField(getString(R.string.ca_subject_cn), getString(R.string.ca_subject_cn_hint))
        subjectContainer.addView(editTextCACN!!)

        contentPadding.addView(subjectContainer)

        // ---- CA Generation / Status (shown when acting as CA) ----
        val generationContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(12), 0, 0)
        }
        caGenerationContainer = generationContainer

        // CA Status
        generationContainer.addView(createSubsectionLabel(getString(R.string.ca_status_title)))

        val statusContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(4), 0, dp(8))
        }
        caStatusContainer = statusContainer

        rootCAStatusText = TextView(this).apply {
            text = "Root CA: ${getString(R.string.ca_status_not_generated)}"
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            setPadding(0, dp(2), 0, dp(2))
        }
        statusContainer.addView(rootCAStatusText!!)

        intermediateCAStatusText = TextView(this).apply {
            text = "Intermediate CA: ${getString(R.string.ca_status_not_generated)}"
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            setPadding(0, dp(2), 0, dp(2))
        }
        statusContainer.addView(intermediateCAStatusText!!)

        generationContainer.addView(statusContainer)

        // Generate buttons
        val buttonRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(4), 0, dp(4))
        }

        val genRootButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.ca_generate_root)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { marginEnd = dp(8) }
            setOnClickListener { onGenerateRootCA() }
        }
        buttonGenerateRoot = genRootButton
        buttonRow.addView(genRootButton)

        val genIntermediateButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.ca_generate_intermediate)
            isEnabled = false
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { onGenerateIntermediateCA() }
        }
        buttonGenerateIntermediate = genIntermediateButton
        buttonRow.addView(genIntermediateButton)

        generationContainer.addView(buttonRow)

        // Reset CA button
        val resetButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.ca_reset)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorError))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(4) }
            setOnClickListener { onResetCA() }
        }
        generationContainer.addView(resetButton)

        // Platform CA Selection
        generationContainer.addView(createDivider())
        generationContainer.addView(createSubsectionLabel(getString(R.string.ca_platform_ca_title)))
        generationContainer.addView(createExplanationText(getString(R.string.ca_platform_ca_explanation)))

        val platformRadioGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            setPadding(0, dp(4), 0, 0)
        }
        platformCARadioGroup = platformRadioGroup

        val rootRadio = RadioButton(this).apply {
            id = View.generateViewId()
            text = getString(R.string.ca_platform_root)
        }
        platformRadioGroup.addView(rootRadio)

        val intermediateRadio = RadioButton(this).apply {
            id = View.generateViewId()
            text = getString(R.string.ca_platform_intermediate)
            isChecked = true
        }
        platformRadioGroup.addView(intermediateRadio)

        platformRadioGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isInitializing) return@setOnCheckedChangeListener
            val alias = if (checkedId == rootRadio.id)
                AndroidCA.ROOT_CA_ALIAS else AndroidCA.INTERMEDIATE_CA_ALIAS
            lifecycleScope.launch {
                trustedComputingSettingsRepository.updatePlatformCAAlias(alias)
            }
        }
        generationContainer.addView(platformRadioGroup)

        contentPadding.addView(generationContainer)

        // ---- Bootstrap Methods sub-section ----
        contentPadding.addView(createDivider())
        contentPadding.addView(createSubsectionLabel(getString(R.string.settings_bootstrap_methods)))
        contentPadding.addView(createExplanationText(getString(R.string.explain_bootstrap)))

        // Auto-Bootstrap toggle
        contentPadding.addView(createSettingRowWithSwitch(
            title = getString(R.string.bootstrap_auto_enabled),
            description = getString(R.string.bootstrap_auto_desc)
        ).also { (_, switch) ->
            switchAutoBootstrap = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                bootstrapMethodsContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                lifecycleScope.launch {
                    bootstrapSettingsRepository.updateAutoBootstrapEnabled(isChecked)
                }
            }
        }.first)

        // Bootstrap methods container (visible only when auto-bootstrap is ON)
        val methodsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        bootstrapMethodsContainer = methodsContainer

        methodsContainer.addView(createDivider())

        // DANE Method
        createMethodSection(
            methodName = "DANE",
            description = getString(R.string.bootstrap_dane_desc),
            onCheckedChange = { isChecked ->
                daneConfigContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                if (!isInitializing) {
                    lifecycleScope.launch {
                        bootstrapSettingsRepository.updateDaneSettings(enabled = isChecked)
                    }
                }
            }
        ).also { (section, checkbox, container) ->
            checkboxDane = checkbox
            daneConfigContainer = container

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_server_url_hint),
                hint = "https://ca.example.com"
            ).also { edit ->
                editTextDaneServerUrl = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentDaneConfig()
                }
            })

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_dns_server_hint),
                hint = "8.8.8.8:53"
            ).also { edit ->
                editTextDaneDnsServer = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentDaneConfig()
                }
            })

            container.addView(createSettingRowWithSwitch(
                title = getString(R.string.bootstrap_dane_dot),
                description = null,
                compact = true
            ).also { (_, switch) ->
                switchDaneDot = switch
                switch.setOnCheckedChangeListener { _, _ ->
                    if (!isInitializing) saveCurrentDaneConfig()
                }
            }.first)

            container.addView(createSettingRowWithSwitch(
                title = getString(R.string.bootstrap_dane_dnssec),
                description = null,
                compact = true
            ).also { (_, switch) ->
                switchDaneDnssec = switch
                switch.setOnCheckedChangeListener { _, _ ->
                    if (!isInitializing) saveCurrentDaneConfig()
                }
            }.first)

            methodsContainer.addView(section)
        }

        // Noise Method
        createMethodSection(
            methodName = "Noise Protocol",
            description = getString(R.string.bootstrap_noise_desc),
            onCheckedChange = { isChecked ->
                noiseConfigContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                if (!isInitializing) {
                    lifecycleScope.launch {
                        bootstrapSettingsRepository.updateNoiseSettings(enabled = isChecked)
                    }
                }
            }
        ).also { (section, checkbox, container) ->
            checkboxNoise = checkbox
            noiseConfigContainer = container

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_noise_server_address),
                hint = getString(R.string.bootstrap_noise_server_hint)
            ).also { edit ->
                editTextNoiseServerAddress = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentNoiseConfig()
                }
            })

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_noise_static_key),
                hint = getString(R.string.bootstrap_static_key_hint)
            ).also { edit ->
                editTextNoiseStaticKey = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentNoiseConfig()
                }
            })

            methodsContainer.addView(section)
        }

        // SPKI Method
        createMethodSection(
            methodName = "SPKI Pinning",
            description = getString(R.string.bootstrap_spki_desc),
            onCheckedChange = { isChecked ->
                spkiConfigContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                if (!isInitializing) {
                    lifecycleScope.launch {
                        bootstrapSettingsRepository.updateSpkiSettings(enabled = isChecked)
                    }
                }
            }
        ).also { (section, checkbox, container) ->
            checkboxSpki = checkbox
            spkiConfigContainer = container

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_server_url_hint),
                hint = "https://ca.example.com"
            ).also { edit ->
                editTextSpkiServerUrl = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentSpkiConfig()
                }
            })

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_spki_pin_label),
                hint = getString(R.string.bootstrap_spki_pin_hint)
            ).also { edit ->
                editTextSpkiPinSha256 = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentSpkiConfig()
                }
            })

            methodsContainer.addView(section)
        }

        // Direct Method
        createMethodSection(
            methodName = "Direct HTTPS",
            description = getString(R.string.bootstrap_direct_desc),
            onCheckedChange = { isChecked ->
                directConfigContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                if (!isInitializing) {
                    lifecycleScope.launch {
                        bootstrapSettingsRepository.updateDirectSettings(enabled = isChecked)
                    }
                }
            }
        ).also { (section, checkbox, container) ->
            checkboxDirect = checkbox
            directConfigContainer = container

            container.addView(createLabeledEditText(
                label = getString(R.string.bootstrap_server_url_hint),
                hint = "https://ca.example.com"
            ).also { edit ->
                editTextDirectServerUrl = edit
                edit.setOnFocusChangeListener { _, hasFocus ->
                    if (!hasFocus && !isInitializing) saveCurrentDirectConfig()
                }
            })

            methodsContainer.addView(section)
        }

        methodsContainer.addView(createDivider())

        // Timeout Spinner
        val timeoutRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, dp(8))
        }
        timeoutRow.addView(TextView(this).apply {
            text = getString(R.string.bootstrap_timeout_label)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })

        val timeoutSpinner = Spinner(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        val timeoutAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            bootstrapTimeoutValues.map { "${it.seconds}s" }
        )
        timeoutAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        timeoutSpinner.adapter = timeoutAdapter
        spinnerBootstrapTimeout = timeoutSpinner

        timeoutSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (isInitializing) return
                val selectedTimeout = bootstrapTimeoutValues.getOrNull(position) ?: BootstrapTimeout.SECONDS_15
                lifecycleScope.launch {
                    bootstrapSettingsRepository.updatePerMethodTimeout(selectedTimeout)
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        timeoutRow.addView(timeoutSpinner)
        methodsContainer.addView(timeoutRow)

        // Run Bootstrap Now button with progress indicator
        val bootstrapActionContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = android.view.Gravity.CENTER_HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(16) }
        }

        val bootstrapProgress = CircularProgressIndicator(this).apply {
            isIndeterminate = true
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = android.view.Gravity.CENTER_HORIZONTAL
                bottomMargin = dp(8)
            }
        }
        bootstrapActionContainer.addView(bootstrapProgress)

        val bootstrapNowButton = com.google.android.material.button.MaterialButton(
            this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            text = "Run Bootstrap Now"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener {
                bootstrapProgress.visibility = View.VISIBLE
                isEnabled = false

                lifecycleScope.launch {
                    try {
                        val settings = bootstrapSettingsRepository.getSettings()
                        if (!settings.hasConfiguredMethod()) {
                            Snackbar.make(
                                card,
                                "No bootstrap methods configured. Enable at least one method above.",
                                Snackbar.LENGTH_LONG
                            ).show()
                            return@launch
                        }

                        val client = BootstrapClient(settings)
                        val result = client.fetchCABundle()

                        var imported = 0
                        for (certDER in result.certificates) {
                            try {
                                val trustedCA = trustStoreRepository.importCertificate(
                                    certDER,
                                    "Bootstrap (${result.method.displayName})"
                                )
                                if (trustedCA != null) imported++
                            } catch (_: Exception) {
                                // Skip failed individual cert imports
                            }
                        }

                        Snackbar.make(
                            card,
                            "Imported $imported certificate(s) via ${result.method.displayName}",
                            Snackbar.LENGTH_LONG
                        ).show()
                    } catch (e: NoMethodsConfiguredException) {
                        Snackbar.make(
                            card,
                            "No bootstrap methods configured. Enable at least one method above.",
                            Snackbar.LENGTH_LONG
                        ).show()
                    } catch (e: BootstrapFailedException) {
                        val methodErrors = e.attempts.joinToString("\n") {
                            "${it.method.displayName}: ${it.error.message}"
                        }
                        Snackbar.make(
                            card,
                            "Bootstrap failed: $methodErrors",
                            Snackbar.LENGTH_LONG
                        ).show()
                    } catch (e: Exception) {
                        Snackbar.make(
                            card,
                            "Bootstrap failed: ${e.message}",
                            Snackbar.LENGTH_LONG
                        ).show()
                    } finally {
                        bootstrapProgress.visibility = View.GONE
                        isEnabled = true
                    }
                }
            }
        }
        bootstrapActionContainer.addView(bootstrapNowButton)

        methodsContainer.addView(bootstrapActionContainer)

        contentPadding.addView(methodsContainer)

        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)
    }

    // -------------------------------------------------------------------------
    // Device Trust Section
    // -------------------------------------------------------------------------

    /**
     * Builds the Device Trust settings section.
     * Contains Trusted Computing toggles and trust store management.
     */
    private fun buildDeviceTrustSection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(6))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_shield,
            title = getString(R.string.settings_section_trust),
            description = getString(R.string.settings_section_trust_desc)
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // Explanation
        contentPadding.addView(createExplanationText(getString(R.string.explain_trusted_computing)))

        // Enable Trusted Computing toggle
        contentPadding.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_trusted_computing_enabled),
            description = getString(R.string.settings_trusted_computing_description)
        ).also { (row, switch) ->
            switchTrustedComputing = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                trustedComputingConditionalContainer?.visibility = if (isChecked) View.VISIBLE else View.GONE
                lifecycleScope.launch {
                    trustedComputingSettingsRepository.updateEnabled(isChecked)
                }
            }
        }.first)

        // Conditional settings container
        val conditionalContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(16), 0, 0)
        }
        trustedComputingConditionalContainer = conditionalContainer

        // Require Trusted IDevID
        conditionalContainer.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_trusted_computing_require_idevid),
            description = getString(R.string.settings_trusted_computing_require_idevid_desc)
        ).also { (_, switch) ->
            switchRequireIDevID = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                lifecycleScope.launch {
                    trustedComputingSettingsRepository.updateRequireTrustedIDevID(isChecked)
                }
            }
        }.first)
        conditionalContainer.addView(createExplanationText(getString(R.string.explain_require_idevid)))

        // Require Full Attestation
        conditionalContainer.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_trusted_computing_full_attestation),
            description = getString(R.string.settings_trusted_computing_full_attestation_desc)
        ).also { (_, switch) ->
            switchFullAttestation = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                lifecycleScope.launch {
                    trustedComputingSettingsRepository.updateRequireFullAttestation(isChecked)
                }
            }
        }.first)
        conditionalContainer.addView(createExplanationText(getString(R.string.explain_full_attestation)))

        // Trust New Devices
        conditionalContainer.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_trusted_computing_trust_new),
            description = getString(R.string.settings_trusted_computing_trust_new_desc)
        ).also { (_, switch) ->
            switchTrustNewDevices = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                lifecycleScope.launch {
                    trustedComputingSettingsRepository.updateTrustNewDevices(isChecked)
                }
            }
        }.first)
        conditionalContainer.addView(createExplanationText(getString(R.string.explain_trust_new_devices)))

        // Manage Trust Store button
        val trustStoreButton = Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.settings_trusted_computing_manage_trust_store)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(16) }
            setOnClickListener {
                startActivity(Intent(this@SettingsActivity, TrustStoreActivity::class.java))
            }
        }
        conditionalContainer.addView(trustStoreButton)

        // Security info
        conditionalContainer.addView(createSecurityInfoBanner(
            getString(R.string.settings_trusted_computing_security_info)
        ))

        contentPadding.addView(conditionalContainer)
        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)
    }

    /**
     * Sets up the Fetch CA Bundle button click listener.
     */
    private fun setupFetchCAButtonListener(button: Button, card: MaterialCardView) {
        button.setOnClickListener {
            val url = editTextCAUrl?.text?.toString()?.trim() ?: ""
            if (url.isBlank()) {
                Snackbar.make(card, "Please enter a CA server URL", Snackbar.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            button.isEnabled = false

            lifecycleScope.launch {
                try {
                    bootstrapSettingsRepository.deriveSettingsFromUrl(url)
                    trustedComputingSettingsRepository.updateXkmsEndpoint(url)

                    val settings = bootstrapSettingsRepository.getSettings()
                    val client = BootstrapClient(settings)
                    val result = client.fetchCABundle()

                    var imported = 0
                    for (certDER in result.certificates) {
                        try {
                            val trustedCA = trustStoreRepository.importCertificate(
                                certDER,
                                "Bootstrap (${result.method.displayName})"
                            )
                            if (trustedCA != null) imported++
                        } catch (e: Exception) {
                            // Skip failed imports
                        }
                    }

                    Snackbar.make(
                        card,
                        "Imported $imported certificate(s) via ${result.method.displayName}",
                        Snackbar.LENGTH_LONG
                    ).show()

                } catch (e: BootstrapFailedException) {
                    val details = StringBuilder("All bootstrap methods failed:\n\n")
                    for (attempt in e.attempts) {
                        details.append("${attempt.method.displayName}: ${attempt.error.message}\n\n")
                    }
                    MaterialAlertDialogBuilder(this@SettingsActivity)
                        .setTitle("Bootstrap Failed")
                        .setMessage(details.toString().trim())
                        .setPositiveButton("OK", null)
                        .show()
                } catch (e: NoMethodsConfiguredException) {
                    MaterialAlertDialogBuilder(this@SettingsActivity)
                        .setTitle("Bootstrap Failed")
                        .setMessage("No bootstrap methods are configured. Please enable at least one method in the Bootstrap Settings section.")
                        .setPositiveButton("OK", null)
                        .show()
                } catch (e: Exception) {
                    Snackbar.make(card, "Failed: ${e.message}", Snackbar.LENGTH_LONG).show()
                } finally {
                    button.isEnabled = true
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Media Signing Section
    // -------------------------------------------------------------------------

    /**
     * Builds the Media Signing settings section.
     * Contains auto-sign toggle, signing key selector, and photo/video toggles.
     */
    private fun buildMediaSigningSection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(6))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_key_signing,
            title = getString(R.string.settings_media_signing_title),
            description = getString(R.string.settings_media_signing_description)
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        val mediaSigningRepo = MediaSigningSettingsRepository(this)
        val keyDao = XKeyDatabase.getInstance(this).keyDao()

        // Auto-sign toggle
        val autoSignSwitch = MaterialSwitch(this).apply {
            text = getString(R.string.settings_media_signing_auto)
            textSize = 15f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(4)
            }
        }

        // Auto-sign description
        val autoSignDesc = TextView(this).apply {
            text = getString(R.string.settings_media_signing_auto_desc)
            textSize = 12f
            setTextColor(ContextCompat.getColor(this@SettingsActivity, android.R.color.darker_gray))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
        }

        // Signing key selector
        val keyLabel = TextView(this).apply {
            text = getString(R.string.settings_media_signing_key)
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(4)
            }
        }

        val keySpinner = Spinner(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(12)
            }
        }

        // Photo/Video toggles
        val signPhotosSwitch = MaterialSwitch(this).apply {
            text = getString(R.string.settings_media_signing_photos)
            textSize = 15f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(4)
            }
        }

        val signVideosSwitch = MaterialSwitch(this).apply {
            text = getString(R.string.settings_media_signing_videos)
            textSize = 15f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        contentPadding.addView(autoSignSwitch)
        contentPadding.addView(autoSignDesc)
        contentPadding.addView(keyLabel)
        contentPadding.addView(keySpinner)
        contentPadding.addView(signPhotosSwitch)
        contentPadding.addView(signVideosSwitch)

        // Config container visibility tied to auto-sign
        val configViews = listOf(keyLabel, keySpinner, signPhotosSwitch, signVideosSwitch)
        fun updateConfigVisibility(enabled: Boolean) {
            val visibility = if (enabled) View.VISIBLE else View.GONE
            configViews.forEach { it.visibility = visibility }
        }

        // Load initial settings and signing keys
        lifecycleScope.launch {
            val settings = mediaSigningRepo.getSettings()
            autoSignSwitch.isChecked = settings.autoSignEnabled
            signPhotosSwitch.isChecked = settings.signPhotos
            signVideosSwitch.isChecked = settings.signVideos
            updateConfigVisibility(settings.autoSignEnabled)

            // Populate key spinner with signing-type keys
            val keys = keyDao.getAll()
            val signingKeys = keys.filter { it.keyType == "signing" || it.keyType == "fido2" }
            val keyNames = signingKeys.map { "${it.label.ifEmpty { it.keyId }} (${it.algorithm})" }
            val keyIds = signingKeys.map { it.keyId }

            if (keyNames.isNotEmpty()) {
                keySpinner.adapter = ArrayAdapter(
                    this@SettingsActivity,
                    android.R.layout.simple_spinner_dropdown_item,
                    keyNames
                )
                // Select current key
                val selectedIndex = keyIds.indexOf(settings.signingKeyId)
                if (selectedIndex >= 0) keySpinner.setSelection(selectedIndex)

                keySpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                        lifecycleScope.launch {
                            mediaSigningRepo.setSigningKeyId(keyIds[position])
                        }
                    }
                    override fun onNothingSelected(parent: AdapterView<*>?) {}
                }
            }
        }

        // Auto-sign toggle listener. The load coroutine above assigns isChecked
        // after this listener exists, so without the guard every visit to
        // Settings re-fires it: it rewrites the setting, logs a settings-changed
        // audit row, and starts the foreground service the user never touched.
        autoSignSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isInitializing) return@setOnCheckedChangeListener
            lifecycleScope.launch {
                mediaSigningRepo.setAutoSignEnabled(isChecked)
                updateConfigVisibility(isChecked)
                if (isChecked) {
                    val intent = Intent(this@SettingsActivity, MediaSigningService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(intent)
                    } else {
                        startService(intent)
                    }
                } else {
                    stopService(Intent(this@SettingsActivity, MediaSigningService::class.java))
                }
            }
        }

        signPhotosSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isInitializing) return@setOnCheckedChangeListener
            lifecycleScope.launch { mediaSigningRepo.setSignPhotos(isChecked) }
        }

        signVideosSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isInitializing) return@setOnCheckedChangeListener
            lifecycleScope.launch { mediaSigningRepo.setSignVideos(isChecked) }
        }

        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)
    }

    // -------------------------------------------------------------------------
    // Connectivity Section
    // -------------------------------------------------------------------------

    /**
     * Builds the Connectivity settings section.
     * Contains USB HSM configuration.
     */
    private fun buildConnectivitySection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(18))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_usb,
            title = getString(R.string.settings_section_connectivity),
            description = getString(R.string.settings_section_connectivity_desc)
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // --- Native USB Mode (primary) ---
        contentPadding.addView(createExplanationText(getString(R.string.explain_usb_native)))

        contentPadding.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_usb_native_title),
            description = getString(R.string.settings_usb_native_description)
        ).also { (row, switch) ->
            switchUsbNative = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                lifecycleScope.launch {
                    usbHsmSettingsRepository.setNativeUsbEnabled(isChecked)
                }
            }
        }.first)

        // --- Developer Options (collapsed; holds the ADB/TCP transport) ---
        contentPadding.addView(createDivider())

        val developerOptionsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        developerOptionsContainer.addView(createExplanationText(getString(R.string.explain_usb_tcp)))

        developerOptionsContainer.addView(createSettingRowWithSwitch(
            title = getString(R.string.settings_usb_tcp_title),
            description = getString(R.string.settings_usb_tcp_description)
        ).also { (_, switch) ->
            switchTcpHsm = switch
            switch.setOnCheckedChangeListener { _, isChecked ->
                if (isInitializing) return@setOnCheckedChangeListener
                lifecycleScope.launch {
                    usbHsmSettingsRepository.setTcpHsmEnabled(isChecked)
                }
            }
        }.first)

        contentPadding.addView(createDisclosureHeader(
            title = getString(R.string.settings_developer_options),
            description = getString(R.string.settings_developer_options_desc),
            content = developerOptionsContainer
        ))
        contentPadding.addView(developerOptionsContainer)

        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)
    }

    // -------------------------------------------------------------------------
    // PIN Management Section
    // -------------------------------------------------------------------------

    /**
     * Builds the PIN Management settings section with gradient header.
     * Displays SO PIN and User PIN status and provides a button to launch
     * the full PIN management activity.
     */
    private fun buildPinManagementSection(parent: LinearLayout) {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(4), dp(6), dp(4), dp(18))
            }
        }
        PremiumCardFactory.setNonInteractive(card)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Gradient header
        cardContent.addView(createSectionHeader(
            iconRes = R.drawable.ic_lock,
            title = "PIN Management",
            description = "SO PIN & User PIN lifecycle management"
        ))

        val contentPadding = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // Explanation
        contentPadding.addView(createExplanationText(
            "Manage Security Officer (SO) and User PINs following the PKCS#11 security model. " +
            "The SO PIN is used for administrative operations; the User PIN protects daily usage."
        ))

        // SO PIN status row
        val soPinStatus = TextView(this).apply {
            text = "SO PIN: Loading..."
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setPadding(0, dp(8), 0, dp(4))
        }
        soPinStatusText = soPinStatus
        contentPadding.addView(soPinStatus)

        // User PIN status row
        val userPinStatus = TextView(this).apply {
            text = "User PIN: Loading..."
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setPadding(0, dp(4), 0, dp(12))
        }
        userPinStatusText = userPinStatus
        contentPadding.addView(userPinStatus)

        // Manage PINs button
        val managePinsButton = com.google.android.material.button.MaterialButton(
            this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            text = "Manage PINs"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(4) }
            setOnClickListener {
                startActivity(Intent(this@SettingsActivity, PinManagementActivity::class.java))
            }
        }
        contentPadding.addView(managePinsButton)

        cardContent.addView(contentPadding)
        card.addView(cardContent)
        parent.addView(card)

        // Load current PIN status asynchronously
        lifecycleScope.launch {
            val pinSettings = pinSettingsRepository.getSettings()
            soPinStatusText?.text = "SO PIN: ${if (pinSettings.soPinSet) "Set" else "Not Set"}"
            userPinStatusText?.text = "User PIN: ${if (pinSettings.userPinSet) "Set" else "Not Set"}"
        }
    }

    // -------------------------------------------------------------------------
    // UI Helper Methods
    // -------------------------------------------------------------------------

    /**
     * Creates a gradient section header with icon, title, and description.
     */
    private fun createSectionHeader(iconRes: Int, title: String, description: String): LinearLayout {
        val headerContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))

            // Apply gradient background
            val primaryColor = UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorPrimary)
            val primaryContainerColor = UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorPrimaryContainer)
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(UIHelpers.applyAlpha(primaryColor, 0.15f), UIHelpers.applyAlpha(primaryContainerColor, 0.3f))
            ).apply {
                cornerRadii = floatArrayOf(dp(16f), dp(16f), dp(16f), dp(16f), 0f, 0f, 0f, 0f)
            }
        }

        // Icon
        val icon = ImageView(this).apply {
            setImageResource(iconRes)
            layoutParams = LinearLayout.LayoutParams(dp(28), dp(28)).apply {
                marginEnd = dp(16)
            }
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorPrimary)
            )
        }
        headerContainer.addView(icon)

        // Text column
        val textColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        textColumn.addView(TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurface))
        })
        textColumn.addView(TextView(this).apply {
            text = description
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
        })
        headerContainer.addView(textColumn)

        return headerContainer
    }

    /**
     * Creates a setting row with title, description, and toggle switch.
     * Returns a Pair of (row layout, switch reference).
     */
    private fun createSettingRowWithSwitch(
        title: String,
        description: String?,
        compact: Boolean = false
    ): Pair<LinearLayout, MaterialSwitch> {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, if (compact) dp(4) else dp(8), 0, if (compact) dp(4) else dp(8))
        }

        val textColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        textColumn.addView(TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
        })
        if (description != null) {
            textColumn.addView(TextView(this).apply {
                text = description
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
                setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            })
        }
        row.addView(textColumn)

        val switch = MaterialSwitch(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { marginStart = dp(16) }
        }
        row.addView(switch)

        return Pair(row, switch)
    }

    /**
     * Creates a clickable disclosure header that expands and collapses [content].
     *
     * [content] must already be `GONE`: the disclosure starts closed, so what it
     * hides is opt-in rather than merely discouraged by the prose beside it.
     */
    private fun createDisclosureHeader(
        title: String,
        description: String,
        content: View
    ): LinearLayout {
        val chevron = ImageView(this).apply {
            setImageResource(R.drawable.ic_expand_more)
            layoutParams = LinearLayout.LayoutParams(dp(24), dp(24)).apply {
                marginStart = dp(16)
            }
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@SettingsActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                )
            )
        }

        val textColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        textColumn.addView(TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge)
            setTextColor(
                UIHelpers.resolveThemeColor(
                    this@SettingsActivity,
                    com.google.android.material.R.attr.colorPrimary
                )
            )
        })
        textColumn.addView(TextView(this).apply {
            text = description
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(
                UIHelpers.resolveThemeColor(
                    this@SettingsActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                )
            )
        })

        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            isClickable = true
            isFocusable = true
            setPadding(0, dp(8), 0, dp(8))
            addView(textColumn)
            addView(chevron)
            contentDescription = title
            setOnClickListener {
                val expanded = content.visibility != View.VISIBLE
                content.visibility = if (expanded) View.VISIBLE else View.GONE
                chevron.rotation = if (expanded) 180f else 0f
            }
        }
    }

    /**
     * Creates a subsection label.
     */
    /**
     * Shows only what the selected authority needs: the endpoint for xkms, the
     * subject and generation controls for this phone's own CA, neither when
     * nothing signs.
     */
    private fun applyCASourceVisibility(source: CertificateAuthoritySource) {
        val local = source == CertificateAuthoritySource.THIS_DEVICE
        caUrlContainer?.visibility =
            if (source == CertificateAuthoritySource.XKMS) View.VISIBLE else View.GONE
        caSubjectContainer?.visibility = if (local) View.VISIBLE else View.GONE
        caGenerationContainer?.visibility = if (local) View.VISIBLE else View.GONE
    }

    private fun createSubsectionLabel(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorPrimary))
            setPadding(0, dp(8), 0, dp(4))
        }
    }

    /**
     * Creates a radio option with description.
     */
    private fun createRadioOption(text: String, description: String, isChecked: Boolean = false): RadioButton {
        return RadioButton(this).apply {
            id = View.generateViewId()
            // The description goes on the button's own second line rather than a
            // sibling TextView: a RadioButton has to stay a direct child of the
            // RadioGroup for mutual exclusivity to work. It was previously
            // accepted and silently dropped, so every settings_*_description
            // string on this screen was invisible.
            this.text = if (description.isBlank()) {
                text
            } else {
                SpannableStringBuilder(text).apply {
                    append("\n")
                    val start = length
                    append(description)
                    setSpan(RelativeSizeSpan(0.8f), start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                    setSpan(
                        ForegroundColorSpan(
                            UIHelpers.resolveThemeColor(
                                this@SettingsActivity,
                                com.google.android.material.R.attr.colorOnSurfaceVariant
                            )
                        ),
                        start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
            }
            this.isChecked = isChecked
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    /**
     * Creates a visual divider.
     */
    private fun createDivider(): View {
        return View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(1)
            ).apply {
                topMargin = dp(16)
                bottomMargin = dp(16)
            }
            setBackgroundColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOutlineVariant))
        }
    }

    /**
     * Creates a security info banner.
     */
    private fun createSecurityInfoBanner(message: String): LinearLayout {
        val banner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(16) }
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorTertiaryContainer),
                UIHelpers.dpToPx(this@SettingsActivity, 12f)
            )
        }

        val icon = ImageView(this).apply {
            setImageResource(R.drawable.ic_shield)
            layoutParams = LinearLayout.LayoutParams(dp(20), dp(20)).apply {
                marginEnd = dp(12)
            }
            imageTintList = android.content.res.ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnTertiaryContainer)
            )
        }
        banner.addView(icon)

        banner.addView(TextView(this).apply {
            text = message
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnTertiaryContainer))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })

        return banner
    }

    /**
     * Creates a method section with checkbox and expandable config container.
     * Returns a Triple of (section view, checkbox, config container).
     * The caller must add the section to the parent layout.
     */
    private fun createMethodSection(
        methodName: String,
        description: String,
        onCheckedChange: (Boolean) -> Unit
    ): Triple<LinearLayout, CheckBox, LinearLayout> {
        val section = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }

        val checkbox = CheckBox(this).apply {
            text = methodName
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
        }
        section.addView(checkbox)

        section.addView(TextView(this).apply {
            text = description
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            setPadding(dp(32), 0, 0, dp(4))
        })

        val configContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(32), dp(8), 0, dp(8))
            visibility = View.GONE
        }
        section.addView(configContainer)

        checkbox.setOnCheckedChangeListener { _, isChecked ->
            onCheckedChange(isChecked)
        }

        return Triple(section, checkbox, configContainer)
    }

    /**
     * Creates a labeled EditText.
     */
    private fun createLabeledEditText(label: String, hint: String): EditText {
        return EditText(this).apply {
            // The label was accepted and dropped, leaving the DANE, SPKI and
            // Direct server-URL fields sharing one identical placeholder and no
            // way to tell them apart — on screen or through a screen reader.
            this.hint = if (hint.isBlank()) label else "$label ($hint)"
            contentDescription = label
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
    }

    /**
     * Creates an italic explanation text styled for user-friendly descriptions.
     */
    private fun createExplanationText(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(this@SettingsActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
            setTypeface(typeface, Typeface.ITALIC)
            setPadding(0, dp(4), 0, dp(8))
        }
    }

    /**
     * Creates a labeled EditText for CA subject fields with focus-lost saving.
     */
    private fun createCASubjectField(label: String, hint: String): EditText {
        return EditText(this).apply {
            this.hint = "$label ($hint)"
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(4) }
            setOnFocusChangeListener { _, hasFocus ->
                if (!hasFocus && !isInitializing) saveCurrentCASubjectConfig()
            }
        }
    }

    /**
     * Converts dp to pixels.
     */
    private fun dp(value: Int): Int = UIHelpers.dpToPxInt(this, value)
    private fun dp(value: Float): Float = UIHelpers.dpToPx(this, value)

    // -------------------------------------------------------------------------
    // CA Generation Methods
    // -------------------------------------------------------------------------

    private fun buildCASubjectFromFields(): CASubject {
        return CASubject(
            cn = editTextCACN?.text?.toString()?.trim() ?: "",
            org = editTextCAOrg?.text?.toString()?.trim() ?: "",
            ou = editTextCAOU?.text?.toString()?.trim() ?: "",
            locality = editTextCALocality?.text?.toString()?.trim() ?: "",
            province = editTextCAProvince?.text?.toString()?.trim() ?: "",
            country = editTextCACountry?.text?.toString()?.trim() ?: ""
        )
    }

    private fun onGenerateRootCA() {
        saveCurrentCASubjectConfig()
        val subject = buildCASubjectFromFields()

        buttonGenerateRoot?.isEnabled = false
        buttonGenerateRoot?.text = getString(R.string.ca_generating)

        lifecycleScope.launch {
            val result = androidCA.generateRootCA(subject)
            when (result) {
                is CAInitResult.Success -> {
                    importCACertToTrustStore(androidCA.getRootCertificate(), "xKey Root CA")
                    Snackbar.make(binding.root, getString(R.string.ca_generated_success), Snackbar.LENGTH_SHORT).show()
                    updateCAStatus()
                }
                is CAInitResult.AlreadyInitialized -> {
                    updateCAStatus()
                }
                is CAInitResult.Error -> {
                    Snackbar.make(binding.root, getString(R.string.ca_generated_error, result.message), Snackbar.LENGTH_LONG).show()
                    buttonGenerateRoot?.isEnabled = true
                    buttonGenerateRoot?.text = getString(R.string.ca_generate_root)
                }
            }
        }
    }

    private fun onGenerateIntermediateCA() {
        if (!androidCA.isRootCAGenerated()) {
            Snackbar.make(binding.root, getString(R.string.ca_root_required), Snackbar.LENGTH_SHORT).show()
            return
        }

        saveCurrentCASubjectConfig()
        val subject = buildCASubjectFromFields()

        buttonGenerateIntermediate?.isEnabled = false
        buttonGenerateIntermediate?.text = getString(R.string.ca_generating)

        lifecycleScope.launch {
            val result = androidCA.generateIntermediateCA(subject)
            when (result) {
                is CAInitResult.Success -> {
                    importCACertToTrustStore(androidCA.getIntermediateCertificate(), "xKey Intermediate CA")
                    Snackbar.make(binding.root, getString(R.string.ca_generated_success), Snackbar.LENGTH_SHORT).show()
                    updateCAStatus()
                }
                is CAInitResult.AlreadyInitialized -> {
                    updateCAStatus()
                }
                is CAInitResult.Error -> {
                    Snackbar.make(binding.root, getString(R.string.ca_generated_error, result.message), Snackbar.LENGTH_LONG).show()
                    buttonGenerateIntermediate?.isEnabled = true
                    buttonGenerateIntermediate?.text = getString(R.string.ca_generate_intermediate)
                }
            }
        }
    }

    private fun onResetCA() {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.ca_reset_title))
            .setMessage(getString(R.string.ca_reset_message))
            .setNegativeButton(getString(R.string.button_cancel), null)
            .setPositiveButton(getString(R.string.ca_reset)) { _, _ ->
                lifecycleScope.launch {
                    androidCA.reset()
                    updateCAStatus()
                    Snackbar.make(binding.root, "CA reset complete", Snackbar.LENGTH_SHORT).show()
                }
            }
            .show()
    }

    private suspend fun importCACertToTrustStore(cert: X509Certificate, label: String) {
        try {
            trustStoreRepository.importInternalCACertificate(cert, label)
        } catch (_: Exception) {
            // Non-critical: trust store import is best-effort
        }
    }

    private fun updateCAStatus() {
        val rootInfo = androidCA.getRootCACertificateInfo()
        val intermediateInfo = androidCA.getIntermediateCACertificateInfo()

        if (rootInfo != null) {
            val status = if (rootInfo.isExpired) getString(R.string.ca_status_expired) else getString(R.string.ca_status_active)
            rootCAStatusText?.text = "Root CA: $status\n${rootInfo.subjectDN}\nExpires: ${java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(rootInfo.notAfter)}"
            buttonGenerateRoot?.isEnabled = false
            buttonGenerateRoot?.text = getString(R.string.ca_generate_root)
            buttonGenerateIntermediate?.isEnabled = true
        } else {
            rootCAStatusText?.text = "Root CA: ${getString(R.string.ca_status_not_generated)}"
            buttonGenerateRoot?.isEnabled = true
            buttonGenerateRoot?.text = getString(R.string.ca_generate_root)
            buttonGenerateIntermediate?.isEnabled = false
        }

        if (intermediateInfo != null) {
            val status = if (intermediateInfo.isExpired) getString(R.string.ca_status_expired) else getString(R.string.ca_status_active)
            intermediateCAStatusText?.text = "Intermediate CA: $status\n${intermediateInfo.subjectDN}\nExpires: ${java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(intermediateInfo.notAfter)}"
            buttonGenerateIntermediate?.isEnabled = false
            buttonGenerateIntermediate?.text = getString(R.string.ca_generate_intermediate)
        } else {
            intermediateCAStatusText?.text = "Intermediate CA: ${getString(R.string.ca_status_not_generated)}"
            // Only enable if root exists
            buttonGenerateIntermediate?.isEnabled = rootInfo != null
            buttonGenerateIntermediate?.text = getString(R.string.ca_generate_intermediate)
        }
    }

    // -------------------------------------------------------------------------
    // Config Save Methods
    // -------------------------------------------------------------------------

    private fun saveCurrentCASubjectConfig() {
        lifecycleScope.launch {
            trustedComputingSettingsRepository.updateCASubject(
                org = editTextCAOrg?.text?.toString()?.trim() ?: "",
                ou = editTextCAOU?.text?.toString()?.trim() ?: "",
                locality = editTextCALocality?.text?.toString()?.trim() ?: "",
                province = editTextCAProvince?.text?.toString()?.trim() ?: "",
                country = editTextCACountry?.text?.toString()?.trim() ?: "",
                cn = editTextCACN?.text?.toString()?.trim() ?: ""
            )
        }
    }

    /**
     * Persists the CA server URL currently typed into the field.
     *
     * A blank field clears the stored URL rather than storing an empty string,
     * so the persisted `caServerURL` stays null when unset.
     */
    private fun saveCurrentCAServerUrl() {
        val url = editTextCAUrl?.text?.toString()?.trim().orEmpty()
        lifecycleScope.launch {
            trustedComputingSettingsRepository.updateXkmsEndpoint(url.ifBlank { null })
        }
    }

    private fun saveCurrentDaneConfig() {
        lifecycleScope.launch {
            bootstrapSettingsRepository.updateDaneSettings(
                serverUrl = editTextDaneServerUrl?.text?.toString()?.trim(),
                dnsServer = editTextDaneDnsServer?.text?.toString()?.trim()?.ifBlank { BootstrapSettingsData.DEFAULT_DNS_SERVER },
                dnsOverTls = switchDaneDot?.isChecked,
                requireDnssec = switchDaneDnssec?.isChecked
            )
        }
    }

    private fun saveCurrentNoiseConfig() {
        lifecycleScope.launch {
            bootstrapSettingsRepository.updateNoiseSettings(
                serverAddr = editTextNoiseServerAddress?.text?.toString()?.trim(),
                serverStaticKey = editTextNoiseStaticKey?.text?.toString()?.trim()
            )
        }
    }

    private fun saveCurrentSpkiConfig() {
        lifecycleScope.launch {
            bootstrapSettingsRepository.updateSpkiSettings(
                serverUrl = editTextSpkiServerUrl?.text?.toString()?.trim(),
                pinSha256 = editTextSpkiPinSha256?.text?.toString()?.trim()
            )
        }
    }

    private fun saveCurrentDirectConfig() {
        lifecycleScope.launch {
            bootstrapSettingsRepository.updateDirectSettings(
                serverUrl = editTextDirectServerUrl?.text?.toString()?.trim()
            )
        }
    }

    // -------------------------------------------------------------------------
    // Settings Loading
    // -------------------------------------------------------------------------

    /**
     * Loads current settings and keeps the screen in sync with them.
     *
     * The biometric settings are *observed* rather than read once: they are also
     * written by the credential-provider flow, by other screens and by a paired
     * desktop, and a screen that reads them a single time in `onCreate` shows a
     * stale value from then on. The collection is scoped to
     * [Lifecycle.State.STARTED], so it stops while the screen is not visible and
     * re-reads on the way back.
     *
     * The remaining repositories have no such external writers and are read
     * once. Both passes run under [populateUi], and the listener guard is not
     * released until both have landed.
     */
    private fun loadSettings() {
        lifecycleScope.launch {
            populateUi {
                loadOneShotSettings()
                oneShotSettingsLoaded = true
            }
        }
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                settingsRepository.settingsFlow.collect { settings ->
                    populateUi {
                        updateUIWithBiometricSettings(settings)
                        biometricSettingsLoaded = true
                    }
                }
            }
        }
    }

    /**
     * Runs one UI-population pass with the listener guard held throughout.
     *
     * Passes may overlap, so the guard is reference-counted: it is only released
     * once no pass is in flight *and* both initial passes have been applied.
     * Everything here runs on the main dispatcher, so the counters need no
     * further synchronisation.
     */
    private suspend fun populateUi(block: suspend () -> Unit) {
        populationPasses++
        isInitializing = true
        try {
            block()
        } finally {
            populationPasses--
            if (populationPasses == 0 && oneShotSettingsLoaded && biometricSettingsLoaded) {
                isInitializing = false
            }
        }
    }

    /**
     * Reads the repositories that only this screen writes, and applies them.
     */
    private suspend fun loadOneShotSettings() {
        // Load credential provider settings
        if (credentialProviderSettingsRepository.isFeatureAvailable()) {
            val credSettings = credentialProviderSettingsRepository.getSettings()
            switchCredentialProvider?.isChecked = credSettings.isEnabled
            buttonOpenSystemSettings?.visibility = if (credSettings.isEnabled) View.VISIBLE else View.GONE
        }

        // Load USB settings
        val usbHsmSettings = usbHsmSettingsRepository.getSettings()
        switchUsbNative?.isChecked = usbHsmSettings.nativeUsbEnabled
        switchTcpHsm?.isChecked = usbHsmSettings.tcpHsmEnabled

        // Load Trusted Computing settings
        val tcSettings = trustedComputingSettingsRepository.getSettings()
        switchTrustedComputing?.isChecked = tcSettings.enabled
        trustedComputingConditionalContainer?.visibility = if (tcSettings.enabled) View.VISIBLE else View.GONE
        when (tcSettings.caSource) {
            CertificateAuthoritySource.XKMS -> radioCAxkms?.isChecked = true
            CertificateAuthoritySource.THIS_DEVICE -> radioCAThisDevice?.isChecked = true
            CertificateAuthoritySource.NONE -> radioCANone?.isChecked = true
        }
        applyCASourceVisibility(tcSettings.caSource)
        editTextCAUrl?.setText(tcSettings.xkmsEndpoint ?: "")
        switchRequireIDevID?.isChecked = tcSettings.requireTrustedIDevID
        switchFullAttestation?.isChecked = tcSettings.requireFullAttestation
        switchTrustNewDevices?.isChecked = tcSettings.trustNewDevices

        // Load CA subject fields
        editTextCAOrg?.setText(tcSettings.caSubjectOrganization)
        editTextCAOU?.setText(tcSettings.caSubjectOU)
        editTextCALocality?.setText(tcSettings.caSubjectLocality)
        editTextCAProvince?.setText(tcSettings.caSubjectProvince)
        editTextCACountry?.setText(tcSettings.caSubjectCountry)
        editTextCACN?.setText(tcSettings.caSubjectCommonName)

        // Load CA status
        updateCAStatus()

        // Load platform CA selection
        val platformRadio = platformCARadioGroup
        if (platformRadio != null && platformRadio.childCount >= 2) {
            val rootRadio = platformRadio.getChildAt(0) as? RadioButton
            val intermediateRadio = platformRadio.getChildAt(1) as? RadioButton
            if (tcSettings.platformCAAlias == AndroidCA.ROOT_CA_ALIAS) {
                rootRadio?.isChecked = true
            } else {
                intermediateRadio?.isChecked = true
            }
        }

        // Load Bootstrap settings
        val bootstrapSettings = bootstrapSettingsRepository.getSettings()
        switchAutoBootstrap?.isChecked = bootstrapSettings.autoBootstrapEnabled
        bootstrapMethodsContainer?.visibility =
            if (bootstrapSettings.autoBootstrapEnabled) View.VISIBLE else View.GONE

        checkboxDane?.isChecked = bootstrapSettings.daneEnabled
        daneConfigContainer?.visibility = if (bootstrapSettings.daneEnabled) View.VISIBLE else View.GONE
        editTextDaneServerUrl?.setText(bootstrapSettings.daneServerUrl)
        editTextDaneDnsServer?.setText(bootstrapSettings.daneDnsServer)
        switchDaneDot?.isChecked = bootstrapSettings.daneDnsOverTls
        switchDaneDnssec?.isChecked = bootstrapSettings.daneRequireDnssec

        checkboxNoise?.isChecked = bootstrapSettings.noiseEnabled
        noiseConfigContainer?.visibility = if (bootstrapSettings.noiseEnabled) View.VISIBLE else View.GONE
        editTextNoiseServerAddress?.setText(bootstrapSettings.noiseServerAddr)
        editTextNoiseStaticKey?.setText(bootstrapSettings.noiseServerStaticKey)

        checkboxSpki?.isChecked = bootstrapSettings.spkiEnabled
        spkiConfigContainer?.visibility = if (bootstrapSettings.spkiEnabled) View.VISIBLE else View.GONE
        editTextSpkiServerUrl?.setText(bootstrapSettings.spkiServerUrl)
        editTextSpkiPinSha256?.setText(bootstrapSettings.spkiPinSha256)

        checkboxDirect?.isChecked = bootstrapSettings.directEnabled
        directConfigContainer?.visibility = if (bootstrapSettings.directEnabled) View.VISIBLE else View.GONE
        editTextDirectServerUrl?.setText(bootstrapSettings.directServerUrl)

        val timeoutIndex = bootstrapTimeoutValues.indexOfFirst { it.seconds == bootstrapSettings.perMethodTimeoutSeconds }
        if (timeoutIndex >= 0) {
            spinnerBootstrapTimeout?.setSelection(timeoutIndex)
        }

        // Load PIN Management status
        val pinSettings = pinSettingsRepository.getSettings()
        soPinStatusText?.text = "SO PIN: ${if (pinSettings.soPinSet) "Set" else "Not Set"}"
        userPinStatusText?.text = "User PIN: ${if (pinSettings.userPinSet) "Set" else "Not Set"}"
    }

    /**
     * Updates UI with biometric settings.
     */
    private fun updateUIWithBiometricSettings(settings: BiometricSettingsData) {
        val isBiometricEnabled = settings.uvPolicy == UserVerificationPolicy.REQUIRED
        switchBiometricAuth?.isChecked = isBiometricEnabled
        updateAuthModeVisibility(isBiometricEnabled)

        when (settings.authMode) {
            BiometricAuthMode.PER_OPERATION -> radioPerOperation?.isChecked = true
            BiometricAuthMode.TIME_WINDOW -> radioTimeWindow?.isChecked = true
            BiometricAuthMode.PER_SESSION -> radioPerSession?.isChecked = true
        }
        updateTimeWindowVisibility(settings.authMode)

        val timeWindowIndex = timeWindowValues.indexOfFirst { it.seconds == settings.timeWindowSeconds }
        if (timeWindowIndex >= 0) {
            spinnerTimeWindow?.setSelection(timeWindowIndex)
        }

        // Attestation policy
        val attestRadioGroup = attestationPolicyRadioGroup
        if (attestRadioGroup != null && attestRadioGroup.childCount >= 3) {
            when (settings.attestationBiometricPolicy) {
                AttestationBiometricPolicy.ALWAYS -> (attestRadioGroup.getChildAt(0) as? RadioButton)?.isChecked = true
                AttestationBiometricPolicy.PAIRED_DEVICES_SKIP -> (attestRadioGroup.getChildAt(1) as? RadioButton)?.isChecked = true
                AttestationBiometricPolicy.NEVER -> (attestRadioGroup.getChildAt(2) as? RadioButton)?.isChecked = true
            }
        }
    }

    /**
     * Updates visibility of authentication mode options.
     */
    private fun updateAuthModeVisibility(isBiometricEnabled: Boolean) {
        authModeContainer?.visibility = if (isBiometricEnabled) View.VISIBLE else View.GONE
        if (!isBiometricEnabled) {
            timeWindowContainer?.visibility = View.GONE
        }
    }

    /**
     * Updates visibility of time window options.
     */
    private fun updateTimeWindowVisibility(authMode: BiometricAuthMode) {
        timeWindowContainer?.visibility = if (authMode == BiometricAuthMode.TIME_WINDOW) View.VISIBLE else View.GONE
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
}

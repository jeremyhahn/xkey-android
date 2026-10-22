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
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.coordinatorlayout.widget.CoordinatorLayout
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.AppBarLayout
import com.google.android.material.appbar.CollapsingToolbarLayout
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs

/**
 * Premium certificate detail activity with collapsing toolbar and premium cards.
 *
 * Displays comprehensive X.509 certificate information parsed from the stored PEM,
 * including extensions (key usage, EKU, SANs, basic constraints), chain verification
 * status, and certificate lifecycle actions.
 *
 * Follows the same UI pattern as [KeyDetailActivity].
 */
class CertificateDetailActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "CertificateDetail"
        const val EXTRA_SERIAL_NUMBER = "serial_number"

        private val CN_REGEX = Regex("CN=([^,]+)")


        private val profileIcons = mapOf(
            "tls-server" to "\uD83D\uDD12",
            "tls-client" to "\uD83D\uDD10",
            "idevid" to "\uD83D\uDCF1",
            "code-signing" to "\u270D\uFE0F",
            "email" to "\u2709\uFE0F",
            "ocsp-responder" to "\u2714\uFE0F",
            "timestamping" to "\u23F0",
            "subordinate-ca" to "\uD83C\uDFDB\uFE0F",
            "ca-root" to "\uD83C\uDFDB\uFE0F",
            "ca-intermediate" to "\uD83C\uDFDB\uFE0F"
        )

        /** Key Usage bit names per RFC 5280. */
        private val KEY_USAGE_NAMES = mapOf(
            0 to "Digital Signature",
            1 to "Non-Repudiation",
            2 to "Key Encipherment",
            3 to "Data Encipherment",
            4 to "Key Agreement",
            5 to "Key Cert Sign",
            6 to "CRL Sign",
            7 to "Encipher Only",
            8 to "Decipher Only"
        )

        /** Common Extended Key Usage OID names. */
        private val EKU_NAMES = mapOf(
            "1.3.6.1.5.5.7.3.1" to "TLS Server Authentication",
            "1.3.6.1.5.5.7.3.2" to "TLS Client Authentication",
            "1.3.6.1.5.5.7.3.3" to "Code Signing",
            "1.3.6.1.5.5.7.3.4" to "Email Protection",
            "1.3.6.1.5.5.7.3.8" to "Time Stamping",
            "1.3.6.1.5.5.7.3.9" to "OCSP Signing"
        )

        /** CRL Reason names per RFC 5280. */
        private val CRL_REASON_NAMES = mapOf(
            0 to "Unspecified",
            1 to "Key Compromise",
            2 to "CA Compromise",
            3 to "Affiliation Changed",
            4 to "Superseded",
            5 to "Cessation of Operation",
            6 to "Certificate Hold",
            9 to "Privilege Withdrawn",
            10 to "AA Compromise"
        )

        /**
         * Opacity of the hero section for [verticalOffset] within [scrollRange].
         *
         * A certificate short enough to leave the app bar nothing to scroll
         * reports a range of zero, and the division that produced the fade then
         * handed the hero a NaN alpha, which draws as nothing at all. Zero range
         * means fully expanded, so the hero stays opaque.
         */
        internal fun heroAlpha(verticalOffset: Int, scrollRange: Int): Float {
            if (scrollRange <= 0) return 1f
            return (1f - abs(verticalOffset).toFloat() / scrollRange).coerceIn(0f, 1f)
        }
    }

    private val certificateDao by lazy { XKeyDatabase.getInstance(this).certificateDao() }
    private val androidCA by lazy { AndroidCA(this).also {
        it.certificateDao = certificateDao
    }}

    private lateinit var coordinatorLayout: CoordinatorLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var heroIconContainer: LinearLayout
    private lateinit var heroTitleText: TextView
    private lateinit var heroSubtitleContainer: LinearLayout

    private var certEntity: CertificateEntity? = null
    private var parsedCert: X509Certificate? = null

    private val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val serialNumber = intent.getStringExtra(EXTRA_SERIAL_NUMBER) ?: run {
            finish()
            return
        }

        buildPremiumLayout()
        loadCertificate(serialNumber)
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
    // Layout
    // -------------------------------------------------------------------------

    private fun buildPremiumLayout() {
        coordinatorLayout = CoordinatorLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(resolveThemeColor(android.R.attr.colorBackground))
        }

        buildAppBar()
        buildScrollContent()

        setContentView(coordinatorLayout)
    }

    private fun buildAppBar() {
        val appBarLayout = AppBarLayout(this).apply {
            layoutParams = CoordinatorLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPxInt(220)
            )
            setBackgroundColor(Color.TRANSPARENT)
        }

        val collapsingToolbar = CollapsingToolbarLayout(this).apply {
            layoutParams = AppBarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                scrollFlags = AppBarLayout.LayoutParams.SCROLL_FLAG_SCROLL or
                        AppBarLayout.LayoutParams.SCROLL_FLAG_EXIT_UNTIL_COLLAPSED
            }
            setContentScrimColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
        }

        val heroContainer = LinearLayout(this).apply {
            layoutParams = CollapsingToolbarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                collapseMode = CollapsingToolbarLayout.LayoutParams.COLLAPSE_MODE_PARALLAX
            }
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dpToPxInt(24), dpToPxInt(56), dpToPxInt(24), dpToPxInt(16))
        }

        heroIconContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPxInt(72), dpToPxInt(72)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(12)
            }
            gravity = Gravity.CENTER
        }

        val heroIcon = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            textSize = 32f
            gravity = Gravity.CENTER
            tag = "hero_icon"
        }
        heroIconContainer.addView(heroIcon)
        heroContainer.addView(heroIconContainer)

        heroTitleText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(8)
            }
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            gravity = Gravity.CENTER
            maxLines = 2
        }
        heroContainer.addView(heroTitleText)

        heroSubtitleContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        heroContainer.addView(heroSubtitleContainer)

        collapsingToolbar.addView(heroContainer)

        val toolbar = Toolbar(this).apply {
            layoutParams = CollapsingToolbarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                resolveActionBarSize()
            ).apply {
                collapseMode = CollapsingToolbarLayout.LayoutParams.COLLAPSE_MODE_PIN
            }
            elevation = 0f
        }

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setDisplayShowTitleEnabled(false)
        }

        collapsingToolbar.addView(toolbar)
        appBarLayout.addView(collapsingToolbar)
        coordinatorLayout.addView(appBarLayout)

        appBarLayout.addOnOffsetChangedListener { appBar, verticalOffset ->
            heroContainer.alpha = heroAlpha(verticalOffset, appBar.totalScrollRange)
        }
    }

    private fun buildScrollContent() {
        val scrollView = NestedScrollView(this).apply {
            layoutParams = CoordinatorLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                behavior = AppBarLayout.ScrollingViewBehavior()
            }
            clipToPadding = false
        }

        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(16), dpToPxInt(8), dpToPxInt(16), dpToPxInt(24))
        }

        scrollView.addView(contentLayout)
        coordinatorLayout.addView(scrollView)
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    private fun loadCertificate(serialNumber: String) {
        lifecycleScope.launch {
            val entity = withContext(Dispatchers.IO) {
                certificateDao.getBySerial(serialNumber)
            }
            if (entity == null) {
                finish()
                return@launch
            }

            certEntity = entity
            parsedCert = parsePEM(entity.certificatePEM)

            updateHeroSection(entity)
            displayCertificateDetails(entity)
            animateContentIn()
        }
    }

    // -------------------------------------------------------------------------
    // Hero
    // -------------------------------------------------------------------------

    private fun updateHeroSection(cert: CertificateEntity) {
        val iconView = heroIconContainer.findViewWithTag<TextView>("hero_icon")
        iconView?.text = profileIcons[cert.profile] ?: "\uD83D\uDCC4"

        val gradientColors = CategoryPalette.certificateGradient(this, cert.profile)

        val iconBackground = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            gradientColors
        ).apply {
            shape = GradientDrawable.OVAL
        }
        heroIconContainer.background = iconBackground

        heroTitleText.text = extractCN(cert.subjectDN)

        heroSubtitleContainer.removeAllViews()

        val status = getCertificateStatus(cert)
        addHeroBadge(getStatusText(status), getStatusColor(status))
        addHeroBadge(getProfileDisplayName(cert.profile), gradientColors[0])
    }

    private fun addHeroBadge(text: String, color: Int) {
        val badge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(8)
            }
            this.text = text
            textSize = 12f
            setTextColor(Color.WHITE)
            setPadding(dpToPxInt(12), dpToPxInt(4), dpToPxInt(12), dpToPxInt(4))
            background = GradientDrawable().apply {
                setColor(UIHelpers.applyAlpha(color, 0.85f))
                cornerRadius = dpToPx(12f)
            }
        }
        heroSubtitleContainer.addView(badge)
    }

    // -------------------------------------------------------------------------
    // Card Content
    // -------------------------------------------------------------------------

    private fun displayCertificateDetails(cert: CertificateEntity) {
        // Reloading after a revoke calls this a second time, and nothing else
        // clears the container — the screen would show two of every card and
        // re-animate them all.
        contentLayout.removeAllViews()
        buildGeneralInfoCard(cert)
        buildValidityCard(cert)
        buildSecurityCard(cert)
        buildKeyUsageCard()
        buildSANCard()
        buildChainCard(cert)
        buildRevocationCard(cert)
        buildActionsCard(cert)
    }

    private fun buildGeneralInfoCard(cert: CertificateEntity) {
        val card = createPremiumCard(
            title = getString(R.string.cert_detail_general_info),
            icon = "\uD83D\uDCCB"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addPremiumDetailRow(content, getString(R.string.cert_detail_subject), cert.subjectDN)
        addPremiumDetailRow(content, getString(R.string.cert_detail_issuer), cert.issuerDN)
        addPremiumDetailRow(content, getString(R.string.cert_detail_serial), cert.serialNumber, isMonospace = true)
        addPremiumDetailRow(content, getString(R.string.cert_detail_profile), getProfileDisplayName(cert.profile))

        contentLayout.addView(card)
    }

    private fun buildValidityCard(cert: CertificateEntity) {
        val card = createPremiumCard(
            title = getString(R.string.cert_detail_validity),
            icon = "\uD83D\uDCC5"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addPremiumDetailRow(content, getString(R.string.cert_detail_not_before), dateFormat.format(Date(cert.notBefore)))
        addPremiumDetailRow(content, getString(R.string.cert_detail_not_after), dateFormat.format(Date(cert.notAfter)))

        val status = getCertificateStatus(cert)
        val statusRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(4)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val statusLabel = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = getString(R.string.cert_detail_status_label)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
        }
        statusRow.addView(statusLabel)

        val statusBadge = createInlineBadge(getStatusText(status), getStatusColor(status))
        val badgeContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            gravity = Gravity.END
        }
        badgeContainer.addView(statusBadge)
        statusRow.addView(badgeContainer)
        content.addView(statusRow)

        contentLayout.addView(card)
    }

    private fun buildSecurityCard(cert: CertificateEntity) {
        val card = createPremiumCard(
            title = getString(R.string.cert_detail_security),
            icon = "\uD83D\uDD12"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addPremiumDetailRow(content, getString(R.string.cert_detail_fingerprint), formatFingerprint(cert.fingerprint), isMonospace = true)

        val x509 = parsedCert
        if (x509 != null) {
            addPremiumDetailRow(content, getString(R.string.cert_detail_signature_algorithm), x509.sigAlgName)

            val basicConstraints = x509.basicConstraints
            if (basicConstraints >= 0) {
                addPremiumDetailRow(
                    content,
                    getString(R.string.cert_detail_is_ca),
                    getString(R.string.cert_detail_value_yes)
                )
                addPremiumDetailRow(
                    content,
                    getString(R.string.cert_detail_path_length),
                    if (basicConstraints == Int.MAX_VALUE) {
                        getString(R.string.cert_detail_path_length_unlimited)
                    } else {
                        basicConstraints.toString()
                    }
                )
            } else if (cert.isCA) {
                addPremiumDetailRow(
                    content,
                    getString(R.string.cert_detail_is_ca),
                    getString(R.string.cert_detail_value_yes)
                )
            }
        }

        contentLayout.addView(card)
    }

    private fun buildKeyUsageCard() {
        val x509 = parsedCert ?: return

        val keyUsageBits = x509.keyUsage
        val ekuList = try { x509.extendedKeyUsage } catch (_: Exception) { null }

        if (keyUsageBits == null && ekuList.isNullOrEmpty()) return

        val card = createPremiumCard(
            title = getString(R.string.cert_detail_key_usage),
            icon = "\uD83D\uDD11"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        if (keyUsageBits != null) {
            val usages = keyUsageBits.indices.mapNotNull { index ->
                if (keyUsageBits[index]) KEY_USAGE_NAMES[index] else null
            }
            if (usages.isNotEmpty()) {
                addPremiumDetailRow(content, getString(R.string.cert_detail_key_usage), usages.joinToString(", "))
            }
        }

        if (!ekuList.isNullOrEmpty()) {
            val ekuNames = ekuList.map { oid -> EKU_NAMES[oid] ?: oid }
            addPremiumDetailRow(content, getString(R.string.cert_detail_ext_key_usage), ekuNames.joinToString(", "))
        }

        contentLayout.addView(card)
    }

    private fun buildSANCard() {
        val x509 = parsedCert ?: return

        val sans = try { x509.subjectAlternativeNames } catch (_: Exception) { null }
        if (sans.isNullOrEmpty()) return

        val card = createPremiumCard(
            title = getString(R.string.cert_detail_san),
            icon = "\uD83C\uDF10"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val dnsNames = mutableListOf<String>()
        val ipAddresses = mutableListOf<String>()
        val emailAddresses = mutableListOf<String>()

        for (san in sans) {
            val type = san[0] as? Int ?: continue
            val value = san[1]?.toString() ?: continue
            when (type) {
                2 -> dnsNames.add(value)      // dNSName
                7 -> ipAddresses.add(value)   // iPAddress
                1 -> emailAddresses.add(value) // rfc822Name
            }
        }

        if (dnsNames.isNotEmpty()) {
            addPremiumDetailRow(content, getString(R.string.cert_detail_dns_names), dnsNames.joinToString("\n"))
        }
        if (ipAddresses.isNotEmpty()) {
            addPremiumDetailRow(content, getString(R.string.cert_detail_ip_addresses), ipAddresses.joinToString("\n"))
        }
        if (emailAddresses.isNotEmpty()) {
            addPremiumDetailRow(content, getString(R.string.cert_detail_email_addresses), emailAddresses.joinToString("\n"))
        }

        contentLayout.addView(card)
    }

    private fun buildChainCard(cert: CertificateEntity) {
        val card = createPremiumCard(
            title = getString(R.string.cert_detail_chain),
            icon = "\uD83D\uDD17"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val x509 = parsedCert
        var verified = false

        if (x509 != null) {
            verified = verifyChain(x509)

            val verifyBadge = createInlineBadge(
                if (verified) getString(R.string.cert_detail_chain_verified) else getString(R.string.cert_detail_chain_unverified),
                if (verified) ContextCompat.getColor(this, android.R.color.holo_green_dark)
                else ContextCompat.getColor(this, android.R.color.holo_orange_light)
            )
            val verifyRow = LinearLayout(this).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = dpToPxInt(8)
                }
                gravity = Gravity.CENTER_VERTICAL
            }

            val verifyLabel = TextView(this).apply {
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
                text = getString(R.string.cert_detail_verification)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
                setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            }
            verifyRow.addView(verifyLabel)

            val badgeWrap = LinearLayout(this).apply {
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
                gravity = Gravity.END
            }
            badgeWrap.addView(verifyBadge)
            verifyRow.addView(badgeWrap)
            content.addView(verifyRow)
        }

        // Show issuer info
        addPremiumDetailRow(content, getString(R.string.cert_detail_issuer), cert.issuerDN)

        // Show chain PEM snippet if available
        if (!cert.chainPEM.isNullOrBlank()) {
            val certCount = cert.chainPEM.split("-----BEGIN CERTIFICATE-----").size - 1
            addPremiumDetailRow(
                content,
                getString(R.string.cert_detail_chain_length),
                getString(R.string.cert_detail_chain_length_value, certCount)
            )
        }

        contentLayout.addView(card)
    }

    private fun buildRevocationCard(cert: CertificateEntity) {
        if (!cert.revoked) return

        val card = createPremiumCard(
            title = getString(R.string.cert_detail_revocation),
            icon = "\u26D4"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addPremiumDetailRow(
            content,
            getString(R.string.cert_detail_revoked_label),
            getString(R.string.cert_detail_value_yes)
        )
        if (cert.revokedAt != null) {
            addPremiumDetailRow(
                content,
                getString(R.string.cert_detail_revoked_at),
                dateFormat.format(Date(cert.revokedAt))
            )
        }
        if (cert.revokedReason != null) {
            val reasonName = CRL_REASON_NAMES[cert.revokedReason] ?: "Unknown (${cert.revokedReason})"
            addPremiumDetailRow(content, getString(R.string.cert_detail_revoke_reason), reasonName)
        }

        contentLayout.addView(card)
    }

    private fun buildActionsCard(cert: CertificateEntity) {
        val card = createPremiumCard(
            title = getString(R.string.cert_detail_actions),
            icon = "\u2699\uFE0F"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        content.addView(createPremiumButton(getString(R.string.cert_detail_export), isPrimary = false) {
            exportCertificatePEM(cert)
        })

        if (!cert.revoked && !cert.isCA) {
            content.addView(createPremiumButton(getString(R.string.cert_detail_revoke), isDanger = true) {
                showRevokeConfirmation(cert)
            })
        }

        content.addView(createPremiumButton(getString(R.string.cert_detail_delete), isDanger = true) {
            showDeleteConfirmation(cert)
        })

        contentLayout.addView(card)
    }

    // -------------------------------------------------------------------------
    // Premium Card Helpers
    // -------------------------------------------------------------------------

    private fun createPremiumCard(title: String, icon: String): MaterialCardView {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(20), dpToPxInt(16), dpToPxInt(20), dpToPxInt(16))
            tag = "card_content"
        }

        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val iconView = TextView(this).apply {
            text = icon
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(10)
            }
        }
        headerRow.addView(iconView)

        val titleView = TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
            letterSpacing = 0.02f
        }
        headerRow.addView(titleView)

        content.addView(headerRow)
        card.addView(content)
        return card
    }

    private fun addPremiumDetailRow(
        parent: LinearLayout,
        label: String,
        value: String,
        isMonospace: Boolean = false
    ) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
        }
        row.addView(labelView)

        val valueView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            typeface = if (isMonospace) Typeface.MONOSPACE else Typeface.DEFAULT_BOLD
            gravity = Gravity.END
            if (isMonospace) {
                textSize = 10f
            }
        }
        row.addView(valueView)

        parent.addView(row)
    }

    private fun createInlineBadge(text: String, color: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(Color.WHITE)
            setPadding(dpToPxInt(10), dpToPxInt(4), dpToPxInt(10), dpToPxInt(4))
            background = GradientDrawable().apply {
                setColor(color)
                cornerRadius = dpToPx(10f)
            }
        }
    }

    private fun createPremiumButton(
        text: String,
        isPrimary: Boolean = true,
        isDanger: Boolean = false,
        onClick: () -> Unit
    ): MaterialButton {
        return MaterialButton(this).apply {
            this.text = text
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(8)
            }

            when {
                isDanger -> {
                    strokeColor = ColorStateList.valueOf(
                        resolveThemeColor(androidx.appcompat.R.attr.colorError)
                    )
                    strokeWidth = dpToPxInt(1)
                    setBackgroundColor(Color.TRANSPARENT)
                    setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorError))
                    rippleColor = ColorStateList.valueOf(
                        UIHelpers.applyAlpha(
                            resolveThemeColor(androidx.appcompat.R.attr.colorError),
                            0.12f
                        )
                    )
                }
                isPrimary -> {
                    setBackgroundColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
                    setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnPrimary))
                }
                else -> {
                    strokeColor = ColorStateList.valueOf(
                        resolveThemeColor(androidx.appcompat.R.attr.colorPrimary)
                    )
                    strokeWidth = dpToPxInt(1)
                    setBackgroundColor(Color.TRANSPARENT)
                    setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
                }
            }

            cornerRadius = dpToPxInt(12)
            setOnClickListener { onClick() }
        }
    }

    private fun animateContentIn() {
        for (i in 0 until contentLayout.childCount) {
            val child = contentLayout.getChildAt(i)
            child.alpha = 0f
            child.translationY = dpToPx(24f)
            child.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(350)
                .setStartDelay(i * 60L)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    // -------------------------------------------------------------------------
    // Certificate Operations
    // -------------------------------------------------------------------------

    private fun exportCertificatePEM(cert: CertificateEntity) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Certificate PEM", cert.certificatePEM))

        AuditLogger.logCertificateExported(
            serialNumber = cert.serialNumber,
            subjectDN = cert.subjectDN,
            format = "PEM"
        )

        Snackbar.make(
            coordinatorLayout,
            getString(R.string.cert_export_copied),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    private fun showRevokeConfirmation(cert: CertificateEntity) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.cert_revoke_title))
            .setMessage(getString(R.string.cert_revoke_message))
            .setPositiveButton(getString(R.string.cert_revoke_confirm)) { _, _ ->
                revokeCertificate(cert)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    private fun revokeCertificate(cert: CertificateEntity) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    certificateDao.revoke(
                        cert.serialNumber,
                        System.currentTimeMillis(),
                        AndroidCA.CRLReason.UNSPECIFIED
                    )
                }

                AuditLogger.logCertificateRevoked(
                    serialNumber = cert.serialNumber,
                    subjectDN = cert.subjectDN,
                    reason = AndroidCA.CRLReason.UNSPECIFIED
                )

                Snackbar.make(
                    coordinatorLayout,
                    getString(R.string.cert_revoke_success),
                    Snackbar.LENGTH_SHORT
                ).show()

                // Reload to reflect new status
                loadCertificate(cert.serialNumber)
            } catch (e: Exception) {
                Log.e(TAG, "Certificate revocation failed", e)
                Snackbar.make(
                    coordinatorLayout,
                    getString(R.string.cert_revoke_error, e.message ?: "Unknown error"),
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun showDeleteConfirmation(cert: CertificateEntity) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.cert_delete_title))
            .setMessage(getString(R.string.cert_delete_message))
            .setPositiveButton(getString(R.string.cert_delete_confirm)) { _, _ ->
                deleteCertificate(cert)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    private fun deleteCertificate(cert: CertificateEntity) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    certificateDao.deleteBySerial(cert.serialNumber)
                    TrustStoreRepository(this@CertificateDetailActivity).deleteCertificate(cert.fingerprint)
                }
                Snackbar.make(
                    coordinatorLayout,
                    getString(R.string.cert_delete_success),
                    Snackbar.LENGTH_SHORT
                ).show()
                finish()
            } catch (e: Exception) {
                Log.e(TAG, "Certificate deletion failed", e)
                Snackbar.make(
                    coordinatorLayout,
                    "Failed to delete certificate",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    // -------------------------------------------------------------------------
    // X.509 Parsing & Verification
    // -------------------------------------------------------------------------

    private fun parsePEM(pem: String): X509Certificate? {
        return try {
            val cleanPem = pem.trim()
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(cleanPem.toByteArray())) as X509Certificate
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse certificate PEM", e)
            null
        }
    }

    private fun verifyChain(cert: X509Certificate): Boolean {
        return try {
            if (androidCA.isInitialized()) {
                // Try to verify against the CA chain
                val rootCert = androidCA.getRootCertificate()
                val intermediateCert = if (androidCA.isIntermediateCAGenerated()) {
                    androidCA.getIntermediateCertificate()
                } else null

                // Check if cert was issued by intermediate CA
                if (intermediateCert != null) {
                    try {
                        cert.verify(intermediateCert.publicKey)
                        return true
                    } catch (_: Exception) {}
                }

                // Check if cert was issued by root CA
                try {
                    cert.verify(rootCert.publicKey)
                    return true
                } catch (_: Exception) {}

                // Self-signed check
                try {
                    cert.verify(cert.publicKey)
                    return true
                } catch (_: Exception) {}
            }
            false
        } catch (e: Exception) {
            Log.w(TAG, "Chain verification failed", e)
            false
        }
    }

    // -------------------------------------------------------------------------
    // Certificate Helpers
    // -------------------------------------------------------------------------

    private fun extractCN(subjectDN: String): String {
        return CN_REGEX.find(subjectDN)?.groupValues?.getOrNull(1) ?: subjectDN
    }

    private fun formatFingerprint(fingerprint: String): String {
        return fingerprint.uppercase().chunked(2).joinToString(":")
    }

    private fun getProfileDisplayName(profile: String): String = when (profile) {
        "tls-server" -> getString(R.string.cert_filter_tls_server)
        "tls-client" -> getString(R.string.cert_filter_tls_client)
        "idevid" -> getString(R.string.cert_filter_idevid)
        "code-signing" -> getString(R.string.cert_filter_code_signing)
        "email" -> getString(R.string.cert_filter_email)
        "ocsp-responder" -> getString(R.string.cert_filter_ocsp)
        "timestamping" -> getString(R.string.cert_filter_timestamping)
        "subordinate-ca" -> getString(R.string.cert_filter_ca)
        "ca-root" -> "Root CA"
        "ca-intermediate" -> "Intermediate CA"
        else -> profile.replaceFirstChar { it.uppercase() }
    }

    private enum class CertStatus {
        VALID, EXPIRED, EXPIRING_SOON, REVOKED, CA
    }

    private fun getCertificateStatus(cert: CertificateEntity): CertStatus {
        val now = System.currentTimeMillis()
        val thirtyDays = 30L * 24 * 60 * 60 * 1000
        return when {
            cert.revoked -> CertStatus.REVOKED
            cert.notAfter < now -> CertStatus.EXPIRED
            cert.notAfter < now + thirtyDays -> CertStatus.EXPIRING_SOON
            cert.isCA -> CertStatus.CA
            else -> CertStatus.VALID
        }
    }

    private fun getStatusText(status: CertStatus): String = when (status) {
        CertStatus.VALID -> getString(R.string.cert_detail_status_valid)
        CertStatus.EXPIRED -> getString(R.string.cert_detail_status_expired)
        CertStatus.EXPIRING_SOON -> getString(R.string.cert_status_expiring)
        CertStatus.REVOKED -> getString(R.string.cert_detail_status_revoked)
        CertStatus.CA -> getString(R.string.cert_detail_status_ca)
    }

    private fun getStatusColor(status: CertStatus): Int = when (status) {
        CertStatus.VALID -> ContextCompat.getColor(this, android.R.color.holo_green_dark)
        CertStatus.EXPIRED -> ContextCompat.getColor(this, android.R.color.holo_red_light)
        CertStatus.EXPIRING_SOON -> ContextCompat.getColor(this, android.R.color.holo_orange_light)
        CertStatus.REVOKED -> ContextCompat.getColor(this, android.R.color.darker_gray)
        CertStatus.CA -> ContextCompat.getColor(this, android.R.color.holo_blue_dark)
    }

    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------

    private fun resolveThemeColor(attr: Int): Int {
        return UIHelpers.resolveThemeColor(this, attr)
    }

    private fun resolveActionBarSize(): Int {
        return UIHelpers.resolveActionBarSize(this)
    }

    private fun dpToPx(dp: Float): Float {
        return UIHelpers.dpToPx(this, dp)
    }

    private fun dpToPxInt(dp: Int): Int {
        return UIHelpers.dpToPxInt(this, dp)
    }
}

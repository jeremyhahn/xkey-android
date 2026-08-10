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

import android.content.Context
import androidx.annotation.ColorRes
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.R

/**
 * The colour a detail screen wears, chosen by what the thing *is*.
 *
 * Key types and certificate profiles used to carry their own hardcoded gradient
 * tables — nineteen entries between two files, six of them duplicated, drawn from
 * a framework's default palette. Nine unrelated hues at inconsistent lightness is
 * what makes a screen look assembled rather than designed.
 *
 * They now resolve to seven [Family] values. Things of the same kind look the
 * same: both TLS profiles are transport, every CA profile is authority. Colour
 * carries the family; the screen already spells out the exact profile in words,
 * so asking colour to encode identity as well buys nothing and costs coherence.
 *
 * The palette itself is generated, not picked — see the note in `colors.xml`.
 */
object CategoryPalette {

    /**
     * What a credential or certificate is *for*. Seven families, because seven
     * is what the domain actually has once near-duplicates are folded together.
     */
    enum class Family(
        @param:ColorRes val startColorRes: Int,
        @param:ColorRes val endColorRes: Int
    ) {
        /** Names a principal: passkeys, IDevIDs, SSH and email identities. */
        IDENTITY(R.color.category_identity_start, R.color.category_identity_end),

        /** Signs for others: every CA in the hierarchy. */
        AUTHORITY(R.color.category_authority_start, R.color.category_authority_end),

        /** Secures a channel: TLS, in either role. */
        TRANSPORT(R.color.category_transport_start, R.color.category_transport_end),

        /** Vouches for hardware state. */
        ATTESTATION(R.color.category_attestation_start, R.color.category_attestation_end),

        /** Keeps something confidential: encryption and symmetric secrets. */
        EXCHANGE(R.color.category_exchange_start, R.color.category_exchange_end),

        /** Proves something was not altered: signing, HMAC, code signing. */
        INTEGRITY(R.color.category_integrity_start, R.color.category_integrity_end),

        /** Speaks to validity over time: OCSP and timestamping. */
        LIFECYCLE(R.color.category_lifecycle_start, R.color.category_lifecycle_end);

        /** The two gradient stops, resolved for the current theme. */
        fun gradient(context: Context): IntArray = intArrayOf(
            ContextCompat.getColor(context, startColorRes),
            ContextCompat.getColor(context, endColorRes)
        )
    }

    /** Unrecognised things get the identity family rather than a stray colour. */
    private val FALLBACK = Family.IDENTITY

    private val KEY_TYPES = mapOf(
        "fido2" to Family.IDENTITY,
        "ssh" to Family.IDENTITY,
        "ca" to Family.AUTHORITY,
        "tls" to Family.TRANSPORT,
        "attestation" to Family.ATTESTATION,
        "encryption" to Family.EXCHANGE,
        "secret" to Family.EXCHANGE,
        "signing" to Family.INTEGRITY,
        "hmac" to Family.INTEGRITY
    )

    private val CERTIFICATE_PROFILES = mapOf(
        "idevid" to Family.IDENTITY,
        "email" to Family.IDENTITY,
        "ca-root" to Family.AUTHORITY,
        "ca-intermediate" to Family.AUTHORITY,
        "subordinate-ca" to Family.AUTHORITY,
        "tls-server" to Family.TRANSPORT,
        "tls-client" to Family.TRANSPORT,
        "code-signing" to Family.INTEGRITY,
        "ocsp-responder" to Family.LIFECYCLE,
        "timestamping" to Family.LIFECYCLE
    )

    /** The family for a `KeyEntity.keyType`. */
    fun forKeyType(keyType: String?): Family = KEY_TYPES[keyType] ?: FALLBACK

    /** The family for a `CertificateEntity.profile`. */
    fun forCertificateProfile(profile: String?): Family =
        CERTIFICATE_PROFILES[profile] ?: FALLBACK

    /** Gradient stops for a key type, resolved for the current theme. */
    fun keyGradient(context: Context, keyType: String?): IntArray =
        forKeyType(keyType).gradient(context)

    /** Gradient stops for a certificate profile, resolved for the current theme. */
    fun certificateGradient(context: Context, profile: String?): IntArray =
        forCertificateProfile(profile).gradient(context)
}

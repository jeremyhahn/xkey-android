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
package com.automatethethings.xkey.ca

import java.util.Date
import java.util.concurrent.TimeUnit

/** The validity window of a certificate the CA is about to sign. */
data class CertificateValidity(val notBefore: Date, val notAfter: Date)

/**
 * The validity window for a certificate valid for [validityDays] days from
 * [now], signed by an issuer valid from [issuerNotBefore] to [issuerNotAfter].
 */
fun validityFor(
    now: Date,
    validityDays: Int,
    issuerNotBefore: Date,
    issuerNotAfter: Date
): CertificateValidity {
    val requestedNotAfter = Date(now.time + TimeUnit.DAYS.toMillis(validityDays.toLong()))
    return validityUntil(now, requestedNotAfter, issuerNotBefore, issuerNotAfter)
}

/**
 * The validity window for a certificate requested to be valid from [now] to
 * [requestedNotAfter], signed by an issuer valid from [issuerNotBefore] to
 * [issuerNotAfter].
 */
@Suppress("UNUSED_PARAMETER")
fun validityUntil(
    now: Date,
    requestedNotAfter: Date,
    issuerNotBefore: Date,
    issuerNotAfter: Date
): CertificateValidity = CertificateValidity(now, requestedNotAfter)

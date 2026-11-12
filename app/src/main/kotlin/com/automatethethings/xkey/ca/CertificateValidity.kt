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
 *
 * @throws IllegalArgumentException if [validityDays] is not positive.
 * @throws IllegalStateException if the issuer is expired or not yet valid at
 *   [now]. See [validityUntil] for the clamp.
 */
fun validityFor(
    now: Date,
    validityDays: Int,
    issuerNotBefore: Date,
    issuerNotAfter: Date
): CertificateValidity {
    require(validityDays > 0) { "Certificate validity must be at least one day, got $validityDays" }
    val requestedNotAfter = Date(now.time + TimeUnit.DAYS.toMillis(validityDays.toLong()))
    return validityUntil(now, requestedNotAfter, issuerNotBefore, issuerNotAfter)
}

/**
 * The validity window for a certificate requested to be valid from [now] to
 * [requestedNotAfter], signed by an issuer valid from [issuerNotBefore] to
 * [issuerNotAfter].
 *
 * A certificate never outlives its issuer: notAfter is the earlier of
 * [requestedNotAfter] and [issuerNotAfter]. An issuer that is expired or not
 * yet valid at [now] issues nothing.
 *
 * @throws IllegalStateException if the issuer is expired or not yet valid at
 *   [now].
 */
fun validityUntil(
    now: Date,
    requestedNotAfter: Date,
    issuerNotBefore: Date,
    issuerNotAfter: Date
): CertificateValidity {
    check(!now.after(issuerNotAfter)) {
        "Issuing CA certificate expired at ${issuerNotAfter.toInstant()}"
    }
    check(!now.before(issuerNotBefore)) {
        "Issuing CA certificate is not valid until ${issuerNotBefore.toInstant()}"
    }
    require(requestedNotAfter.after(now)) {
        "Certificate notAfter ${requestedNotAfter.toInstant()} is not after notBefore ${now.toInstant()}"
    }
    val notAfter = if (requestedNotAfter.after(issuerNotAfter)) issuerNotAfter else requestedNotAfter
    return CertificateValidity(notBefore = now, notAfter = notAfter)
}

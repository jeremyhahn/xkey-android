/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.x509.Certificate as Asn1Certificate
import java.security.MessageDigest

/**
 * Derives the per-device pairing fingerprint bound to the **attested key**
 * (issue #93 / go-xkms PR #124): the SHA-256 of the attested leaf certificate's
 * `SubjectPublicKeyInfo` — the public half of the key generated inside the
 * TEE / StrongBox and certified by the attestation chain.
 *
 * This replaces the older "SHA-256 of the attestation **root** certificate",
 * which was a Google Hardware Attestation Root shared by every handset under it
 * (a vendor identity, not a device identity). The attested key is device-unique,
 * and hashing the KEY rather than the whole leaf DER keeps the value STABLE
 * across an honest re-attestation of the same key (which re-issues the leaf with
 * a fresh serial, validity window and challenge but leaves the key unchanged)
 * and changes it only when the device regenerates its attested key.
 *
 * ## Wire contract
 *
 * The desktop (go-xkms) stores this value at pairing and, on reconnect,
 * byte-compares the value the phone echoes in the identity ack and mixes it into
 * the Noise prologue (`software/docs/12-xkey-android-wire-contract.md`). go-xkms
 * derives it as `sha256(cert.RawSubjectPublicKeyInfo)` over the VERIFIED leaf, so
 * the two platforms MUST hash identical bytes.
 *
 * To guarantee that, this hashes the `SubjectPublicKeyInfo` extracted straight
 * from the certificate DER via the ASN.1 structure — never a re-encoded
 * [java.security.PublicKey.getEncoded], whose EC parameter encoding (named-curve
 * OID vs. explicit parameters, point form) is provider-dependent and can differ
 * from the bytes the certificate actually carries. For the P-256 named-curve
 * keys Android attestation uses, the certificate's SPKI is already canonical DER,
 * so the DER re-encode below is byte-identical to Go's `RawSubjectPublicKeyInfo`.
 */
object AttestedKeyFingerprint {

    /**
     * The 32 raw bytes `SHA-256(SubjectPublicKeyInfo DER)` of the attested leaf
     * certificate [leafCertDer] (DER-encoded X.509). These are the exact bytes
     * the phone echoes on reconnect (`[IDENTITY_ACK_KNOWN | fingerprint(32)]`).
     */
    fun of(leafCertDer: ByteArray): ByteArray {
        val spkiDer = Asn1Certificate.getInstance(leafCertDer)
            .subjectPublicKeyInfo
            .getEncoded(ASN1Encoding.DER)
        return MessageDigest.getInstance("SHA-256").digest(spkiDer)
    }

    /**
     * Lowercase hex of [of] — the form persisted in
     * [com.automatethethings.xkey.settings.PairedDeviceRepository] and converted
     * back to 32 bytes for the wire.
     */
    fun hexOf(leafCertDer: ByteArray): String =
        of(leafCertDer).joinToString("") { "%02x".format(it) }
}

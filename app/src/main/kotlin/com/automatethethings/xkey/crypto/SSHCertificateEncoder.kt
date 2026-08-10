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
package com.automatethethings.xkey.crypto

import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * OpenSSH certificate wire format encoder.
 *
 * Implements the binary format from OpenSSH's PROTOCOL.certkeys specification.
 * Supports ECDSA (P-256, P-384, P-521) and RSA certificate types.
 *
 * SSH certificates are signed blobs containing a public key, validity constraints,
 * and extensions. This encoder builds the certificate body and produces the final
 * signed certificate string suitable for use with `ssh-keygen -L -f`.
 */
object SSHCertificateEncoder {

    const val SSH_CERT_TYPE_USER = 1
    const val SSH_CERT_TYPE_HOST = 2

    /**
     * Build the certificate body (everything before the signature).
     *
     * @param subjectPublicKey The public key being certified
     * @param serial Certificate serial number (uint64)
     * @param certType SSH_CERT_TYPE_USER (1) or SSH_CERT_TYPE_HOST (2)
     * @param keyId Key identifier string
     * @param validPrincipals List of valid principal names
     * @param validAfter Start of validity window (Unix timestamp)
     * @param validBefore End of validity window (Unix timestamp)
     * @param criticalOptions Map of critical options (sorted by key)
     * @param extensions Map of extensions (sorted by key)
     * @param caPublicKey The CA's public key (for the signature key field)
     * @return The certificate body bytes
     */
    fun buildCertificateBody(
        subjectPublicKey: PublicKey,
        serial: Long,
        certType: Int,
        keyId: String,
        validPrincipals: List<String>,
        validAfter: Long,
        validBefore: Long,
        criticalOptions: Map<String, String>,
        extensions: Map<String, String>,
        caPublicKey: PublicKey
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // Type string
        writeSSHString(out, getCertTypeString(subjectPublicKey).toByteArray(Charsets.UTF_8))

        // Nonce (32 random bytes)
        val nonce = ByteArray(32)
        SecureRandom().nextBytes(nonce)
        writeSSHString(out, nonce)

        // Public key fields (curve-specific)
        writePublicKeyFields(out, subjectPublicKey)

        // Serial (uint64)
        writeUint64(out, serial)

        // Type (uint32)
        writeUint32(out, certType)

        // Key ID (string)
        writeSSHString(out, keyId.toByteArray(Charsets.UTF_8))

        // Valid principals (string list packed into a single string)
        val principalsBlob = ByteArrayOutputStream()
        for (principal in validPrincipals) {
            writeSSHString(principalsBlob, principal.toByteArray(Charsets.UTF_8))
        }
        writeSSHString(out, principalsBlob.toByteArray())

        // Validity window
        writeUint64(out, validAfter)
        writeUint64(out, validBefore)

        // Critical options (sorted map, each value wrapped as nested SSH string)
        writeSortedOptions(out, criticalOptions)

        // Extensions (sorted map, each value wrapped as nested SSH string)
        writeSortedOptions(out, extensions)

        // Reserved (empty string)
        writeSSHString(out, ByteArray(0))

        // Signature key (CA public key in SSH wire format)
        writeSSHString(out, encodePublicKeyBlob(caPublicKey))

        return out.toByteArray()
    }

    /**
     * Build a complete signed SSH certificate string.
     *
     * @param body The certificate body from [buildCertificateBody]
     * @param sign Callback that signs the body bytes and returns the raw signature.
     *             For ECDSA, this should return DER-encoded signature from Android Keystore.
     * @param caPublicKey The CA's public key (to determine signature algorithm)
     * @return Full OpenSSH certificate line: "{type} {base64-data}"
     */
    fun buildSignedCertificate(
        body: ByteArray,
        sign: (ByteArray) -> ByteArray,
        caPublicKey: PublicKey
    ): String {
        val rawSignature = sign(body)

        // Build the signature blob: string(algorithm) || string(signature-data)
        val signatureBlob = ByteArrayOutputStream()
        val sigAlgorithm = getPlainKeyTypeString(caPublicKey)
        writeSSHString(signatureBlob, sigAlgorithm.toByteArray(Charsets.UTF_8))

        when (caPublicKey) {
            is ECPublicKey -> {
                // ECDSA: Convert DER signature to SSH format (two mpints: r, s)
                val (r, s) = decodeDERSignature(rawSignature)
                val ecSigBlob = ByteArrayOutputStream()
                writeSSHMPInt(ecSigBlob, r)
                writeSSHMPInt(ecSigBlob, s)
                writeSSHString(signatureBlob, ecSigBlob.toByteArray())
            }
            is RSAPublicKey -> {
                // RSA: signature is used as-is
                writeSSHString(signatureBlob, rawSignature)
            }
            else -> throw IllegalArgumentException("Unsupported CA key type: ${caPublicKey.algorithm}")
        }

        // Assemble full certificate: body || string(signature-blob)
        val certBytes = ByteArrayOutputStream()
        certBytes.write(body)
        writeSSHString(certBytes, signatureBlob.toByteArray())

        // Extract cert type string from the body (first SSH string field)
        val typeStrLen = ((body[0].toInt() and 0xFF) shl 24) or
            ((body[1].toInt() and 0xFF) shl 16) or
            ((body[2].toInt() and 0xFF) shl 8) or
            (body[3].toInt() and 0xFF)
        val typeStr = String(body, 4, typeStrLen, Charsets.UTF_8)

        val base64 = Base64.encodeToString(certBytes.toByteArray(), Base64.NO_WRAP)
        return "$typeStr $base64"
    }

    /**
     * Encode a PublicKey as an SSH wire format blob.
     *
     * @param publicKey EC or RSA public key
     * @return SSH wire format blob bytes
     */
    fun encodePublicKeyBlob(publicKey: PublicKey): ByteArray {
        val out = ByteArrayOutputStream()
        val keyType = getPlainKeyTypeString(publicKey)
        writeSSHString(out, keyType.toByteArray(Charsets.UTF_8))

        when (publicKey) {
            is ECPublicKey -> {
                val params = publicKey.params
                val fieldSize = params.curve.field.fieldSize
                val (curveName, coordinateSize) = when (fieldSize) {
                    256 -> "nistp256" to 32
                    384 -> "nistp384" to 48
                    521 -> "nistp521" to 66
                    else -> throw IllegalArgumentException("Unsupported EC field size: $fieldSize")
                }
                writeSSHString(out, curveName.toByteArray(Charsets.UTF_8))
                val x = padCoordinate(publicKey.w.affineX.toByteArray(), coordinateSize)
                val y = padCoordinate(publicKey.w.affineY.toByteArray(), coordinateSize)
                val ecPoint = byteArrayOf(0x04) + x + y
                writeSSHString(out, ecPoint)
            }
            is RSAPublicKey -> {
                writeSSHMPInt(out, publicKey.publicExponent.toByteArray())
                writeSSHMPInt(out, publicKey.modulus.toByteArray())
            }
            else -> {
                // Check for EdEC key type (API 33+)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    publicKey is java.security.interfaces.EdECPublicKey) {
                    val rawBytes = edECPointToBytes(publicKey.point)
                    writeSSHString(out, rawBytes)
                } else {
                    throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
                }
            }
        }

        return out.toByteArray()
    }

    /**
     * Get the SSH certificate type string for a public key.
     *
     * E.g., "ecdsa-sha2-nistp256-cert-v01@openssh.com"
     */
    fun getCertTypeString(publicKey: PublicKey): String = when (publicKey) {
        is ECPublicKey -> {
            val fieldSize = publicKey.params.curve.field.fieldSize
            when (fieldSize) {
                256 -> "ecdsa-sha2-nistp256-cert-v01@openssh.com"
                384 -> "ecdsa-sha2-nistp384-cert-v01@openssh.com"
                521 -> "ecdsa-sha2-nistp521-cert-v01@openssh.com"
                else -> throw IllegalArgumentException("Unsupported EC field size: $fieldSize")
            }
        }
        is RSAPublicKey -> "ssh-rsa-cert-v01@openssh.com"
        else -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                publicKey is java.security.interfaces.EdECPublicKey) {
                "ssh-ed25519-cert-v01@openssh.com"
            } else {
                throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
            }
        }
    }

    /**
     * Get the plain (non-certificate) SSH key type string.
     *
     * E.g., "ecdsa-sha2-nistp256", "ssh-rsa"
     */
    fun getPlainKeyTypeString(publicKey: PublicKey): String = when (publicKey) {
        is ECPublicKey -> {
            val fieldSize = publicKey.params.curve.field.fieldSize
            when (fieldSize) {
                256 -> "ecdsa-sha2-nistp256"
                384 -> "ecdsa-sha2-nistp384"
                521 -> "ecdsa-sha2-nistp521"
                else -> throw IllegalArgumentException("Unsupported EC field size: $fieldSize")
            }
        }
        is RSAPublicKey -> "ssh-rsa"
        else -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                publicKey is java.security.interfaces.EdECPublicKey) {
                "ssh-ed25519"
            } else {
                throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
            }
        }
    }

    // -------------------------------------------------------------------------
    // Wire format helpers
    // -------------------------------------------------------------------------

    fun writeSSHString(out: ByteArrayOutputStream, data: ByteArray) {
        writeUint32(out, data.size)
        out.write(data)
    }

    fun writeSSHMPInt(out: ByteArrayOutputStream, data: ByteArray) {
        writeSSHString(out, data)
    }

    fun writeUint32(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 24) and 0xFF)
        out.write((value shr 16) and 0xFF)
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    fun writeUint64(out: ByteArrayOutputStream, value: Long) {
        out.write(((value shr 56) and 0xFF).toInt())
        out.write(((value shr 48) and 0xFF).toInt())
        out.write(((value shr 40) and 0xFF).toInt())
        out.write(((value shr 32) and 0xFF).toInt())
        out.write(((value shr 24) and 0xFF).toInt())
        out.write(((value shr 16) and 0xFF).toInt())
        out.write(((value shr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }

    /**
     * Pad or trim an EC coordinate to the required size.
     *
     * BigInteger.toByteArray() may return a leading zero byte (sign byte) or
     * fewer bytes than required.
     */
    fun padCoordinate(bytes: ByteArray, size: Int): ByteArray = when {
        bytes.size == size -> bytes
        bytes.size > size -> bytes.takeLast(size).toByteArray()
        else -> ByteArray(size - bytes.size) + bytes
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Write public key fields into the certificate body (without the key type prefix,
     * which is already written as the cert type string).
     */
    private fun writePublicKeyFields(out: ByteArrayOutputStream, publicKey: PublicKey) {
        when (publicKey) {
            is ECPublicKey -> {
                val params = publicKey.params
                val fieldSize = params.curve.field.fieldSize
                val (curveName, coordinateSize) = when (fieldSize) {
                    256 -> "nistp256" to 32
                    384 -> "nistp384" to 48
                    521 -> "nistp521" to 66
                    else -> throw IllegalArgumentException("Unsupported EC field size: $fieldSize")
                }
                writeSSHString(out, curveName.toByteArray(Charsets.UTF_8))
                val x = padCoordinate(publicKey.w.affineX.toByteArray(), coordinateSize)
                val y = padCoordinate(publicKey.w.affineY.toByteArray(), coordinateSize)
                val ecPoint = byteArrayOf(0x04) + x + y
                writeSSHString(out, ecPoint)
            }
            is RSAPublicKey -> {
                writeSSHMPInt(out, publicKey.publicExponent.toByteArray())
                writeSSHMPInt(out, publicKey.modulus.toByteArray())
            }
            else -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    publicKey is java.security.interfaces.EdECPublicKey) {
                    val rawBytes = edECPointToBytes(publicKey.point)
                    writeSSHString(out, rawBytes)
                } else {
                    throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
                }
            }
        }
    }

    /**
     * Convert an EdECPoint to a 32-byte Ed25519 public key per RFC 8032.
     *
     * The y coordinate is stored in little-endian format with the high bit
     * of the last byte encoding the x coordinate parity.
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun edECPointToBytes(point: java.security.spec.EdECPoint): ByteArray {
        val y = point.y.toByteArray()
        // Convert from big-endian to little-endian 32-byte format per RFC 8032
        val result = ByteArray(32)
        for (i in y.indices.reversed()) {
            if (y.size - 1 - i < 32) {
                result[y.size - 1 - i] = y[i]
            }
        }
        if (point.isXOdd) {
            result[31] = (result[31].toInt() or 0x80).toByte()
        }
        return result
    }

    /**
     * Write a sorted map of options/extensions in SSH certificate format.
     *
     * Each entry is: string(name) || string(data)
     * Where data is itself an SSH string (even empty values are a 4-byte zero-length string).
     */
    private fun writeSortedOptions(out: ByteArrayOutputStream, options: Map<String, String>) {
        val optionsBlob = ByteArrayOutputStream()
        for (key in options.keys.sorted()) {
            writeSSHString(optionsBlob, key.toByteArray(Charsets.UTF_8))
            val value = options[key]!!
            if (value.isEmpty()) {
                // Empty value: a string containing an empty string (4 zero bytes)
                val emptyWrapped = ByteArrayOutputStream()
                writeSSHString(emptyWrapped, ByteArray(0))
                writeSSHString(optionsBlob, emptyWrapped.toByteArray())
            } else {
                // Non-empty value: a string containing another string
                val wrappedValue = ByteArrayOutputStream()
                writeSSHString(wrappedValue, value.toByteArray(Charsets.UTF_8))
                writeSSHString(optionsBlob, wrappedValue.toByteArray())
            }
        }
        writeSSHString(out, optionsBlob.toByteArray())
    }

    /**
     * Decode a DER-encoded ECDSA signature into (r, s) components.
     *
     * DER format: SEQUENCE { INTEGER r, INTEGER s }
     * Returns the raw byte arrays for r and s (BigInteger two's complement).
     */
    private fun decodeDERSignature(der: ByteArray): Pair<ByteArray, ByteArray> {
        // DER: 0x30 <total-len> 0x02 <r-len> <r-bytes> 0x02 <s-len> <s-bytes>
        var offset = 0
        if (der[offset++].toInt() != 0x30) {
            throw IllegalArgumentException("Invalid DER signature: expected SEQUENCE tag")
        }
        // Skip total length (may be 1 or 2 bytes)
        val totalLen = der[offset++].toInt() and 0xFF
        if (totalLen and 0x80 != 0) {
            // Long form length — skip additional length bytes
            val numLenBytes = totalLen and 0x7F
            offset += numLenBytes
        }

        // Read r
        if (der[offset++].toInt() != 0x02) {
            throw IllegalArgumentException("Invalid DER signature: expected INTEGER tag for r")
        }
        val rLen = der[offset++].toInt() and 0xFF
        val r = der.copyOfRange(offset, offset + rLen)
        offset += rLen

        // Read s
        if (der[offset++].toInt() != 0x02) {
            throw IllegalArgumentException("Invalid DER signature: expected INTEGER tag for s")
        }
        val sLen = der[offset++].toInt() and 0xFF
        val s = der.copyOfRange(offset, offset + sLen)

        return Pair(r, s)
    }
}

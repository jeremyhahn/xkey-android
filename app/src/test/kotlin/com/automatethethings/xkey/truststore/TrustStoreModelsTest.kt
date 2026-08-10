/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.truststore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the value types the trust store hands to its callers.
 *
 * These types are the vocabulary of a trust decision, and the call sites branch
 * on them: the repository rebuilds a [TrustedCA] with `copy` on every
 * system-install refresh, and both the pairing path and the UI switch over
 * [VerificationResult] / [IDevIDVerificationResult]. Structural equality is what
 * makes "nothing changed, do not rewrite the metadata" correct, and the
 * `data object` verdicts must stay distinguishable from one another rather than
 * collapsing into a single "not trusted" case.
 */
class TrustStoreModelsTest {

    private fun trustedCA(
        fingerprint: String = "ab".repeat(32),
        label: String? = "corp root",
        systemInstalled: Boolean = false
    ) = TrustedCA(
        fingerprint = fingerprint,
        subjectDN = "CN=Corp Root CA,O=Corp",
        issuerDN = "CN=Corp Root CA,O=Corp",
        notBefore = 1_600_000_000_000L,
        notAfter = 1_900_000_000_000L,
        label = label,
        importedAt = 1_700_000_000_000L,
        source = "manual",
        systemInstalled = systemInstalled
    )

    // -------------------------------------------------------------------------
    // TrustedCA
    // -------------------------------------------------------------------------

    @Test
    fun `TrustedCA compares by content`() {
        val a = trustedCA()
        val b = trustedCA()

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertEquals(a, a.copy())
        assertFalse(a.equals(null))
        assertFalse(a.equals("not a certificate"))
    }

    @Test
    fun `TrustedCA entries with different fingerprints differ`() {
        assertNotEquals(trustedCA(fingerprint = "ab".repeat(32)), trustedCA(fingerprint = "cd".repeat(32)))
    }

    @Test
    fun `flipping the system-installed flag produces a different value`() {
        val stored = trustedCA(systemInstalled = false)

        val installed = stored.copy(systemInstalled = true)

        assertNotEquals(stored, installed)
        assertFalse(stored.systemInstalled)
        assertTrue(installed.systemInstalled)
        assertEquals(stored.fingerprint, installed.fingerprint)
        assertEquals(stored.label, installed.label)
        assertEquals(stored.importedAt, installed.importedAt)
    }

    @Test
    fun `a re-labelled certificate keeps every other field`() {
        val original = trustedCA(label = "old")

        val renamed = original.copy(label = null)

        assertNull(renamed.label)
        assertEquals(original.subjectDN, renamed.subjectDN)
        assertEquals(original.issuerDN, renamed.issuerDN)
        assertEquals(original.notBefore, renamed.notBefore)
        assertEquals(original.notAfter, renamed.notAfter)
        assertEquals(original.source, renamed.source)
    }

    @Test
    fun `TrustedCA toString carries the fields the UI displays`() {
        val text = trustedCA().toString()

        assertTrue(text, text.contains("fingerprint=${"ab".repeat(32)}"))
        assertTrue(text, text.contains("subjectDN=CN=Corp Root CA,O=Corp"))
        assertTrue(text, text.contains("source=manual"))
    }

    @Test
    fun `a list of trust anchors compares element by element`() {
        val before = listOf(trustedCA(fingerprint = "ab".repeat(32)), trustedCA(fingerprint = "cd".repeat(32)))
        val unchanged = listOf(trustedCA(fingerprint = "ab".repeat(32)), trustedCA(fingerprint = "cd".repeat(32)))
        val changed = before.map { it.copy(systemInstalled = true) }

        // This is exactly the check refreshSystemInstallStatus uses to decide
        // whether the metadata needs rewriting at all.
        assertEquals(before, unchanged)
        assertNotEquals(before, changed)
    }

    // -------------------------------------------------------------------------
    // ImportResult
    // -------------------------------------------------------------------------

    @Test
    fun `ImportResult compares by content`() {
        val a = ImportResult(imported = 2, skipped = 1, errors = listOf("bad cert"))
        val b = ImportResult(imported = 2, skipped = 1, errors = listOf("bad cert"))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(skipped = 0))
        assertNotEquals(a, a.copy(errors = emptyList()))
    }

    @Test
    fun `an empty ImportResult reports nothing happened`() {
        val empty = ImportResult(0, 0, emptyList())

        assertEquals(0, empty.imported)
        assertEquals(0, empty.skipped)
        assertTrue(empty.errors.isEmpty())
        assertTrue(empty.toString(), empty.toString().contains("imported=0"))
    }

    // -------------------------------------------------------------------------
    // VerificationResult
    // -------------------------------------------------------------------------

    @Test
    fun `VerificationResult Valid carries its trust level`() {
        val valid = VerificationResult.Valid("hardware-backed")

        assertEquals("hardware-backed", valid.trustLevel)
        assertEquals(valid, VerificationResult.Valid("hardware-backed"))
        assertEquals(valid.hashCode(), VerificationResult.Valid("hardware-backed").hashCode())
        assertNotEquals(valid, VerificationResult.Valid("external-ca"))
        assertTrue(valid.toString(), valid.toString().contains("hardware-backed"))
    }

    @Test
    fun `VerificationResult Invalid carries its error`() {
        val invalid = VerificationResult.Invalid("unable to find valid certification path")

        assertEquals("unable to find valid certification path", invalid.error)
        assertEquals(invalid, invalid.copy())
        assertNotEquals(invalid, VerificationResult.Invalid("other"))
    }

    @Test
    fun `the VerificationResult verdicts stay distinguishable`() {
        val verdicts = listOf<VerificationResult>(
            VerificationResult.Valid("external-ca"),
            VerificationResult.Invalid("expired"),
            VerificationResult.SelfSigned,
            VerificationResult.NoTrustAnchors
        )

        val selfSigned: VerificationResult = VerificationResult.SelfSigned
        val noAnchors: VerificationResult = VerificationResult.NoTrustAnchors

        assertEquals(verdicts.size, verdicts.toSet().size)
        assertSame(VerificationResult.SelfSigned, selfSigned)
        assertNotEquals(selfSigned, noAnchors)
        assertEquals("SelfSigned", VerificationResult.SelfSigned.toString())
        assertEquals("NoTrustAnchors", VerificationResult.NoTrustAnchors.toString())
    }

    // -------------------------------------------------------------------------
    // IDevIDVerificationResult
    // -------------------------------------------------------------------------

    @Test
    fun `IDevIDVerificationResult Trusted carries the leaf details`() {
        val trusted = IDevIDVerificationResult.Trusted(
            trustLevel = "android-ca",
            subjectDN = "CN=laptop",
            notAfter = 1_900_000_000_000L,
            fingerprint = "ef".repeat(32)
        )

        assertEquals(trusted, trusted.copy())
        assertEquals(trusted.hashCode(), trusted.copy().hashCode())
        assertNotEquals(trusted, trusted.copy(trustLevel = "external-ca"))
        assertNotEquals(trusted, trusted.copy(fingerprint = "00".repeat(32)))
        assertTrue(trusted.toString(), trusted.toString().contains("CN=laptop"))
    }

    @Test
    fun `IDevIDVerificationResult Untrusted and Error carry their reasons`() {
        val untrusted = IDevIDVerificationResult.Untrusted("No trusted CA certificates configured")
        val error = IDevIDVerificationResult.Error("store offline")
        val asVerdicts: List<IDevIDVerificationResult> = listOf(untrusted, error)

        assertEquals("No trusted CA certificates configured", untrusted.reason)
        assertEquals("store offline", error.message)
        assertEquals(untrusted, untrusted.copy())
        assertNotEquals(asVerdicts[0], asVerdicts[1])
        assertNotEquals(error, IDevIDVerificationResult.Error("other"))
    }

    @Test
    fun `the IDevID verdicts stay distinguishable`() {
        val verdicts = listOf<IDevIDVerificationResult>(
            IDevIDVerificationResult.Trusted("android-ca", "CN=laptop", 1L, "ef".repeat(32)),
            IDevIDVerificationResult.Untrusted("no anchors"),
            IDevIDVerificationResult.Error("boom"),
            IDevIDVerificationResult.SelfSigned,
            IDevIDVerificationResult.NoCertificate
        )

        assertEquals(verdicts.size, verdicts.toSet().size)
        assertEquals("SelfSigned", IDevIDVerificationResult.SelfSigned.toString())
        assertEquals("NoCertificate", IDevIDVerificationResult.NoCertificate.toString())
    }

    // -------------------------------------------------------------------------
    // CABundleFetchException
    // -------------------------------------------------------------------------

    @Test
    fun `CABundleFetchException keeps its message and cause`() {
        val cause = java.io.IOException("connection reset")
        val withCause = CABundleFetchException("Network error fetching CA bundle", cause)
        val bare = CABundleFetchException("No valid certificates found")

        assertEquals("Network error fetching CA bundle", withCause.message)
        assertSame(cause, withCause.cause)
        assertNull(bare.cause)
    }
}

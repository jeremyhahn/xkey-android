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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for certificate issuance helpers.
 *
 * Tests the SAN parsing logic and profile option configuration used by
 * CertificateManagementActivity. These are pure logic tests that don't
 * require Android framework.
 */
class CertificateIssuanceTest {

    // -------------------------------------------------------------------------
    // SAN Parsing Tests
    // -------------------------------------------------------------------------

    @Test
    fun `parseSANs returns empty lists for blank input`() {
        val (first, second) = parseSANs("", isEmail = false)
        assertTrue(first.isEmpty())
        assertTrue(second.isEmpty())
    }

    @Test
    fun `parseSANs returns empty lists for whitespace input`() {
        val (first, second) = parseSANs("   \n  \n  ", isEmail = false)
        assertTrue(first.isEmpty())
        assertTrue(second.isEmpty())
    }

    @Test
    fun `parseSANs separates DNS names from IPv4 addresses`() {
        val input = "example.com\n192.0.2.1\nwww.example.com\n198.51.100.1"
        val (dnsNames, ipAddresses) = parseSANs(input, isEmail = false)

        assertEquals(listOf("example.com", "www.example.com"), dnsNames)
        assertEquals(listOf("192.0.2.1", "198.51.100.1"), ipAddresses)
    }

    @Test
    fun `parseSANs detects IPv6 addresses`() {
        val input = "example.com\n::1\n2001:db8::1"
        val (dnsNames, ipAddresses) = parseSANs(input, isEmail = false)

        assertEquals(listOf("example.com"), dnsNames)
        assertEquals(listOf("::1", "2001:db8::1"), ipAddresses)
    }

    @Test
    fun `parseSANs treats all entries as email when isEmail is true`() {
        val input = "user@example.com\nadmin@example.com"
        val (emails, second) = parseSANs(input, isEmail = true)

        assertEquals(listOf("user@example.com", "admin@example.com"), emails)
        assertTrue(second.isEmpty())
    }

    @Test
    fun `parseSANs trims whitespace from each line`() {
        val input = "  example.com  \n  192.0.2.1  "
        val (dnsNames, ipAddresses) = parseSANs(input, isEmail = false)

        assertEquals(listOf("example.com"), dnsNames)
        assertEquals(listOf("192.0.2.1"), ipAddresses)
    }

    @Test
    fun `parseSANs skips empty lines`() {
        val input = "example.com\n\n\nwww.example.com"
        val (dnsNames, _) = parseSANs(input, isEmail = false)

        assertEquals(2, dnsNames.size)
    }

    @Test
    fun `parseSANs handles single DNS entry`() {
        val (dnsNames, ipAddresses) = parseSANs("example.com", isEmail = false)

        assertEquals(listOf("example.com"), dnsNames)
        assertTrue(ipAddresses.isEmpty())
    }

    @Test
    fun `parseSANs handles single IP entry`() {
        val (dnsNames, ipAddresses) = parseSANs("198.51.100.1", isEmail = false)

        assertTrue(dnsNames.isEmpty())
        assertEquals(listOf("198.51.100.1"), ipAddresses)
    }

    // -------------------------------------------------------------------------
    // Helper - mirrors the logic from CertificateManagementActivity.parseSANs
    // -------------------------------------------------------------------------

    private fun parseSANs(text: String, isEmail: Boolean): Pair<List<String>, List<String>> {
        if (text.isBlank()) return Pair(emptyList(), emptyList())
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (isEmail) {
            return Pair(lines, emptyList())
        }
        val ipRegex = Regex("""^\d+\.\d+\.\d+\.\d+$|^.*:.*:.*$""")
        val dnsNames = mutableListOf<String>()
        val ipAddresses = mutableListOf<String>()
        for (line in lines) {
            if (ipRegex.matches(line)) {
                ipAddresses.add(line)
            } else {
                dnsNames.add(line)
            }
        }
        return Pair(dnsNames, ipAddresses)
    }
}

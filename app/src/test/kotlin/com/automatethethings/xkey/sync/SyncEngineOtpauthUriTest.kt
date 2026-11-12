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

package com.automatethethings.xkey.sync

import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

/**
 * [otpauthUri] percent-encodes the issuer and account it puts in the label
 * and the `issuer` query parameter (#133), so a synced credential whose
 * issuer or account holds a space, `&`, `?`, `#` or `/` keeps its label and
 * query intact when `OathRepository.importFromUri` parses it.
 */
class SyncEngineOtpauthUriTest {

    private val issuer = "ACME & Co / Ops"
    private val account = "alice smith?#@example.com"

    private fun uri(type: String = "totp", counter: Long? = null) = otpauthUri(
        type = type,
        issuer = issuer,
        accountName = account,
        secret = "JBSWY3DPEHPK3PXP",
        algorithm = "SHA1",
        digits = 6,
        period = 30,
        counter = counter
    )

    @Test
    fun `issuer and account are percent-encoded`() {
        assertEquals(
            "otpauth://totp/ACME%20%26%20Co%20%2F%20Ops:alice%20smith%3F%23%40example.com" +
                "?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20%26%20Co%20%2F%20Ops" +
                "&algorithm=SHA1&digits=6&period=30",
            uri()
        )
    }

    @Test
    fun `the parsed label and query give back the issuer and account`() {
        val parsed = URI(uri(type = "hotp", counter = 7))

        assertEquals("hotp", parsed.host)
        assertEquals("/$issuer:$account", parsed.path)
        val query = parsed.rawQuery.split("&").associate {
            val (k, v) = it.split("=", limit = 2)
            k to URLDecoder.decode(v, Charsets.UTF_8)
        }
        assertEquals(
            mapOf(
                "secret" to "JBSWY3DPEHPK3PXP",
                "issuer" to issuer,
                "algorithm" to "SHA1",
                "digits" to "6",
                "period" to "30",
                "counter" to "7"
            ),
            query
        )
    }

    @Test
    fun `a plain issuer and account are unchanged and no issuer leaves the label bare`() {
        val plain = otpauthUri("totp", null, "alice", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, null)

        assertEquals("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30", plain)
    }
}

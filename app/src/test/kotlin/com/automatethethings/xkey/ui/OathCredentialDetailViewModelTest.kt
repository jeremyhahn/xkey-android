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

import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.ui.OathCredentialDetailUiState.Gone
import com.automatethethings.xkey.ui.OathCredentialDetailUiState.Shown
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [OathCredentialDetailViewModel]: every field of a TOTP and an HOTP
 * credential, the code and the seconds left off a fixed clock (RFC 6238 and
 * RFC 4226 vectors), the remote device id only when set, deletion, and no
 * secret anywhere in the state.
 */
class OathCredentialDetailViewModelTest {

    /** The RFC 4226 / RFC 6238 SHA-1 test secret. */
    private val secret = "12345678901234567890".toByteArray(Charsets.US_ASCII)

    private val rows = mutableMapOf<String, OathCredentialEntity>()

    private fun viewModel(oathId: String, nowMs: Long = 59_000L) = OathCredentialDetailViewModel(
        oathId = oathId,
        load = { id -> rows[id] },
        secretOf = { secret.copyOf() },
        clock = { nowMs }
    )

    @Test
    fun `a TOTP credential shows every field, its code and the seconds left`() = runBlocking {
        rows["totp"] = totp()
        val vm = viewModel("totp", nowMs = 59_000L)

        vm.refresh()

        val d = (vm.state.value as Shown).details
        assertEquals("totp", d.oathId)
        assertEquals("Example", d.issuer)
        assertEquals("user@example.com", d.accountName)
        assertEquals("TOTP", d.type)
        assertEquals("SHA1", d.algorithm)
        assertEquals(6, d.digits)
        assertEquals(30, d.periodSeconds)
        assertNull(d.counter)
        assertEquals(1_700_000_000_000L, d.createdAt)
        assertEquals(1_700_000_100_000L, d.lastUsedAt)
        assertEquals(4, d.useCount)
        assertEquals("local", d.source)
        assertNull(d.remoteDeviceId)
        // RFC 6238 appendix B, T = 59 s, SHA-1: 94287082 (8 digits) -> 287082.
        assertEquals("287082", d.code)
        assertEquals(1, d.secondsLeft)
    }

    @Test
    fun `the seconds left count down with the clock`() = runBlocking {
        rows["totp"] = totp()
        var now = 30_000L
        val vm = OathCredentialDetailViewModel("totp", { rows[it] }, { secret.copyOf() }, { now })

        vm.refresh()
        assertEquals(30, (vm.state.value as Shown).details.secondsLeft)
        now = 47_000L
        vm.refresh()
        assertEquals(13, (vm.state.value as Shown).details.secondsLeft)
    }

    @Test
    fun `an eight digit TOTP code matches the RFC 6238 vector`() = runBlocking {
        rows["totp8"] = totp(oathId = "totp8", digits = 8)
        val vm = viewModel("totp8", nowMs = 1_111_111_109_000L)

        vm.refresh()

        assertEquals("07081804", (vm.state.value as Shown).details.code)
    }

    @Test
    fun `an HOTP credential shows its counter and the code at it, no period`() = runBlocking {
        rows["hotp"] = totp(oathId = "hotp").copy(oathType = "HOTP", counter = 1, lastUsedAt = null, useCount = 0)
        val vm = viewModel("hotp")

        vm.refresh()

        val d = (vm.state.value as Shown).details
        assertEquals("HOTP", d.type)
        assertEquals(1L, d.counter)
        assertNull(d.periodSeconds)
        assertNull(d.secondsLeft)
        assertNull(d.lastUsedAt)
        assertEquals(0, d.useCount)
        // RFC 4226 appendix D, count 1.
        assertEquals("287082", d.code)
    }

    @Test
    fun `a synced credential shows its remote device id`() = runBlocking {
        rows["remote"] = totp(oathId = "remote").copy(source = "remote", remoteDeviceId = "device-01")
        val vm = viewModel("remote")

        vm.refresh()

        val d = (vm.state.value as Shown).details
        assertEquals("remote", d.source)
        assertEquals("device-01", d.remoteDeviceId)
    }

    @Test
    fun `a deleted credential closes the screen`() = runBlocking {
        rows["totp"] = totp()
        val vm = viewModel("totp")
        vm.refresh()
        assertTrue(vm.state.value is Shown)

        rows.remove("totp")
        vm.refresh()

        assertEquals(Gone, vm.state.value)
    }

    @Test
    fun `run stops once the credential is gone`() = runBlocking {
        val vm = viewModel("missing")

        vm.run(tickMillis = 1L)

        assertEquals(Gone, vm.state.value)
    }

    @Test
    fun `copy goes through the clipboard choke point and refreshes`() = runBlocking {
        rows["hotp"] = totp(oathId = "hotp").copy(oathType = "HOTP", counter = 0)
        val vm = viewModel("hotp")
        vm.refresh()
        val clipboard = mockk<OathCodeClipboard>()
        coEvery { clipboard.copy(any(), "755224") } answers {
            rows["hotp"] = rows.getValue("hotp").copy(counter = 1)
            "755224"
        }

        assertEquals("755224", vm.copy(clipboard))

        val d = (vm.state.value as Shown).details
        assertEquals(1L, d.counter)
        assertEquals("287082", d.code)
    }

    @Test
    fun `the state carries no secret`() = runBlocking {
        rows["totp"] = totp()
        val vm = viewModel("totp")
        vm.refresh()

        val fieldNames = OathCredentialDetails::class.java.declaredFields.map { it.name.lowercase() }
        assertFalse(fieldNames.any { "secret" in it })
        val rendered = (vm.state.value as Shown).details.toString()
        assertFalse(rendered.contains("12345678901234567890"))
        assertFalse(rendered.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
    }

    private fun totp(oathId: String = "totp", digits: Int = 6) = OathCredentialEntity(
        oathId = oathId,
        oathType = "TOTP",
        algorithm = "SHA1",
        digits = digits,
        periodSeconds = 30,
        issuer = "Example",
        accountName = "user@example.com",
        secretEncrypted = byteArrayOf(0x01, 0x02),
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_100_000L,
        useCount = 4
    )
}

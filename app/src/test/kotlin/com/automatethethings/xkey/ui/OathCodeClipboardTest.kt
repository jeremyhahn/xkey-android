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

import android.app.Application
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * [OathCodeClipboard], the one copy path of the OATH screens: the clip is
 * marked sensitive, a TOTP copy leaves the credential alone and an HOTP copy
 * takes its code from [OathRepository.generateCode], which advances the
 * counter.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class OathCodeClipboardTest {

    private lateinit var context: Context
    private lateinit var clipboard: ClipboardManager
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        repository = mockk(relaxed = true)
    }

    @Test
    fun `the clip is marked sensitive on API 33 and later`() = runBlocking {
        OathCodeClipboard.create(context, repository).copy(credential("TOTP"), "287082")

        val clip = clipboard.primaryClip!!
        assertEquals("287082", clip.getItemAt(0).text.toString())
        assertTrue(clip.description.extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE))
        assertEquals(OathCodeClipboard.CLIP_LABEL, clip.description.label.toString())
    }

    @Test
    fun `a TOTP copy copies the code shown and leaves the counter alone`() = runBlocking {
        val copied = OathCodeClipboard.create(context, repository).copy(credential("TOTP"), "287082")

        assertEquals("287082", copied)
        assertEquals("287082", clipboard.primaryClip!!.getItemAt(0).text.toString())
        coVerify(exactly = 0) { repository.generateCode(any()) }
    }

    @Test
    fun `an HOTP copy copies the code generateCode returns`() = runBlocking {
        coEvery { repository.generateCode("hotp-1") } returns "755224"

        val copied = OathCodeClipboard.create(context, repository)
            .copy(credential("HOTP", oathId = "hotp-1"), shownCode = "000000")

        assertEquals("755224", copied)
        assertEquals("755224", clipboard.primaryClip!!.getItemAt(0).text.toString())
        coVerify(exactly = 1) { repository.generateCode("hotp-1") }
    }

    @Test
    fun `each HOTP copy advances to a fresh code`() = runBlocking {
        coEvery { repository.generateCode("hotp-1") } returnsMany listOf("755224", "287082")
        val copier = OathCodeClipboard.create(context, repository)
        val hotp = credential("HOTP", oathId = "hotp-1")

        assertEquals("755224", copier.copy(hotp, "755224"))
        assertEquals("287082", copier.copy(hotp, "755224"))
        assertEquals("287082", clipboard.primaryClip!!.getItemAt(0).text.toString())
        coVerify(exactly = 2) { repository.generateCode("hotp-1") }
    }

    private fun credential(type: String, oathId: String = "id-$type") = OathCredentialEntity(
        oathId = oathId,
        oathType = type,
        algorithm = "SHA1",
        issuer = "Example",
        accountName = "user@example.com",
        secretEncrypted = byteArrayOf(0x00),
        createdAt = 0L
    )
}

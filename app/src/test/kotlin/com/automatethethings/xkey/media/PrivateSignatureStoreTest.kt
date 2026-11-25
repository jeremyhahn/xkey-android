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
package com.automatethethings.xkey.media

import android.content.ContentResolver
import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.IOException

/**
 * On API 30+ the app may not write to a camera's files, so the automatic
 * signer's in-file write is refused (EACCES). The signature must then be
 * kept where verification still finds it, never dropped with a log line.
 */
class PrivateSignatureStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val video = ByteArray(256) { it.toByte() }

    @Before
    fun setUp() {
        XmpMetadataHelper.privateStore = PrivateSignatureStore(tempFolder.newFolder("media-signatures"))
    }

    @After
    fun tearDown() {
        XmpMetadataHelper.privateStore = null
    }

    private fun data() = ContentAuthenticityData(
        contentHash = MediaHasher.hashBytes(video),
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "fp",
                signerName = "Camera key",
                algorithm = "ES256",
                value = "sig",
                timestamp = "2026-11-24T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    private fun resolver(uri: Uri): ContentResolver = mockk {
        every { getType(uri) } returns "video/mp4"
        every { openInputStream(uri) } answers { ByteArrayInputStream(video) }
    }

    @Test
    fun `a refused in-file write leaves a signature verification reads from the URI`() {
        val uri = mockk<Uri>()
        val data = data()

        val where = XmpMetadataHelper.persistSignature(data) { throw IOException("open failed: EACCES") }

        assertEquals(XmpMetadataHelper.SignatureLocation.PRIVATE_STORE, where)
        assertEquals(data, XmpMetadataHelper.readSignatureFromUri(resolver(uri), uri, "video/mp4"))
    }

    @Test
    fun `a refused write with a SecurityException also falls back`() {
        val data = data()

        val where = XmpMetadataHelper.persistSignature(data) { throw SecurityException("no write access") }

        assertEquals(XmpMetadataHelper.SignatureLocation.PRIVATE_STORE, where)
        assertEquals(data, XmpMetadataHelper.privateStore!!.get(data.contentHash))
    }

    @Test
    fun `an in-file write that succeeds keeps nothing in the store`() {
        val data = data()

        val where = XmpMetadataHelper.persistSignature(data) { }

        assertEquals(XmpMetadataHelper.SignatureLocation.IN_FILE, where)
        assertNull(XmpMetadataHelper.privateStore!!.get(data.contentHash))
    }

    @Test
    fun `nowhere to keep the signature throws so the caller audits a failure`() {
        XmpMetadataHelper.privateStore = null
        try {
            XmpMetadataHelper.persistSignature(data()) { throw IOException("open failed: EACCES") }
            fail("a signature with nowhere to go must not pass silently")
        } catch (_: IOException) {
        }
    }

    @Test
    fun `a content hash that is not hex is refused as a store key`() {
        val store = XmpMetadataHelper.privateStore!!
        assertNull(store.get("../../shared_prefs/x"))
        try {
            store.put(data().copy(contentHash = "../escape"))
            fail("a non-hex key must be refused")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `an unsigned URI reads as no signature`() {
        val uri = mockk<Uri>()
        assertNull(XmpMetadataHelper.readSignatureFromUri(resolver(uri), uri, "video/mp4"))
    }
}

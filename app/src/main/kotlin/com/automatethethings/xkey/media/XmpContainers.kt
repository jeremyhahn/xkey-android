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
package com.automatethethings.xkey.media

import java.io.InputStream

/** Stub: the embedded XMP containers land in the next commit. */
object XmpContainers {

    enum class Format { ISO_BMFF, PNG, WEBP }

    const val XKEY_NAMESPACE = "http://ns.automatethethings.com/xkey/media/1.0/"

    val XMP_UUID: ByteArray = ByteArray(16)

    fun formatOf(mimeType: String?): Format? = null

    fun packet(json: String): ByteArray = ByteArray(0)

    fun jsonFromPacket(packet: ByteArray): String? = null

    fun embed(data: ByteArray, format: Format, json: String): ByteArray? = null

    fun extract(data: ByteArray, format: Format): String? = null

    fun strip(data: ByteArray, format: Format): ByteArray = data

    fun read(input: InputStream, format: Format): String? = null
}

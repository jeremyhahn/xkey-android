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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.ConcurrentHashMap

/**
 * The one way a media signing job starts: at most one job per URI is in
 * flight, and no more jobs hold memory at once than [memoryBound] allows
 * when each may hold up to [perJobBytes] (at least one always runs).
 * MediaStore notifies a capture several times, and a burst delivers many
 * captures at once: without this, each notification would start its own job
 * and their memory would add up without bound.
 */
internal class MediaJobGate(val memoryBound: Long, val perJobBytes: Long) {

    /** How many jobs may hold memory at once. */
    val maxConcurrent: Int = (memoryBound / perJobBytes.coerceAtLeast(1)).coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()

    private val inFlight: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val permits = Semaphore(maxConcurrent)

    /**
     * Launch [block] in [scope] for [key] once a memory permit is free, or
     * return null without launching when a job for [key] is already in
     * flight. The key is released when the job ends, however it ends.
     */
    fun launch(scope: CoroutineScope, key: String, block: suspend () -> Unit): Job? {
        if (!inFlight.add(key)) return null
        val job = scope.launch(start = CoroutineStart.LAZY) { permits.withPermit { block() } }
        job.invokeOnCompletion { inFlight.remove(key) }
        job.start()
        return job
    }

    companion object {
        /**
         * The signer's gate: one job holds memory at a time. Hashing and
         * container embeds stream, but a JPEG embed holds the image and its
         * rewrite in memory, bounded by [XmpMetadataHelper.maxEmbedBytes]
         * per job.
         */
        fun forSigning(): MediaJobGate {
            val perJob = XmpMetadataHelper.maxEmbedBytes.toLong()
            return MediaJobGate(memoryBound = perJob, perJobBytes = perJob)
        }
    }
}

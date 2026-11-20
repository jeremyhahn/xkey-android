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

/**
 * The most recent URIs, at most [bound] of them: [add] is the one way in,
 * and it drops the least recently added URI once the set is over [bound], so
 * no outcome (signed, queued for access, refused) grows it without limit.
 * Adding a URI already here makes it the most recent again. Safe to use from
 * several threads at once.
 */
class RecentUris(private val bound: Int = DEFAULT_BOUND) {

    init {
        require(bound > 0) { "bound must be positive" }
    }

    private val entries = object : LinkedHashMap<String, Unit>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Unit>?): Boolean = size > bound
    }

    /** Remember [uri]; true when it was not already here. */
    fun add(uri: String): Boolean = synchronized(entries) { entries.put(uri, Unit) == null }

    /** Whether [uri] is among the most recent; this does not change its recency. */
    fun contains(uri: String): Boolean = synchronized(entries) { entries.containsKey(uri) }

    val size: Int
        get() = synchronized(entries) { entries.size }

    companion object {
        /** How many handled captures the media signing service remembers. */
        const val DEFAULT_BOUND = 1000
    }
}

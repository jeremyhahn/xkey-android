package com.automatethethings.xkey.testing

import android.os.Looper
import org.junit.Assert.fail
import org.robolectric.Shadows.shadowOf

/**
 * The one wait for a Robolectric test whose state is set by a real thread
 * (a DataStore or Room executor): it runs the main looper until the state
 * holds. A test whose work runs on a dispatcher it drives idles the looper
 * once and asserts instead.
 */
object MainLooperWait {

    /** Sized for a loaded CI runner; a wait that passes returns as soon as its state holds. */
    const val DEADLINE_MS = 60_000L

    private const val POLL_MS = 10L

    /** Runs the main looper until [done] holds; returns false if it never did within [DEADLINE_MS]. */
    fun holds(done: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + DEADLINE_MS * 1_000_000
        while (true) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return true
            if (System.nanoTime() - deadline > 0) return false
            Thread.sleep(POLL_MS)
        }
    }

    /** Runs the main looper until [done] holds; fails with [what] if it never did within [DEADLINE_MS]. */
    fun until(what: String, done: () -> Boolean) {
        if (!holds(done)) fail(what)
    }
}

package com.automatethethings.xkey.settings

import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * A paired-device store whose encrypted prefs cannot be read (the keystore
 * is unavailable) reads as empty: the failure never escapes into a caller
 * such as an audit record. An update still refuses it, so the empty read is
 * never written back over every pairing.
 */
class PairedDeviceStoreReadTest {

    private val unreadable = mockk<SharedPreferences>(relaxed = true).also {
        every { it.getString(any(), any()) } throws SecurityException("keystore unavailable")
    }

    @Test
    fun anUnreadableStoreReadsAsNoDevices() {
        val repo = PairedDeviceRepository(unreadable)

        assertEquals(emptyList<PairedDeviceData>(), repo.getAllDevices())
        assertNull(repo.getDevice(PEER))
        assertFalse(repo.isDeviceKnown(PEER))
    }

    @Test
    fun anUpdateToAnUnreadableStoreWritesNothing() {
        val repo = PairedDeviceRepository(unreadable)

        assertThrows(SecurityException::class.java) { repo.addDevice(PEER, "desktop") }
        assertThrows(SecurityException::class.java) { repo.removeDevice(PEER) }
        verify(exactly = 0) { unreadable.edit() }
    }

    private companion object {
        const val PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
    }
}

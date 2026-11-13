package com.automatethethings.xkey.settings

import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A paired-device store whose encrypted prefs cannot be read (the keystore
 * is unavailable) is never taken for a store with no record: the one device
 * read, lookupDevice, says Unreadable, getDevice throws rather than answer
 * null, and an update refuses it, so the failed read is never written back
 * over every pairing. Only the display list reads it as empty.
 */
class PairedDeviceStoreReadTest {

    private val unreadable = mockk<SharedPreferences>(relaxed = true).also {
        every { it.getString(any(), any()) } throws SecurityException("keystore unavailable")
    }

    @Test
    fun anUnreadableStoreIsNeverReadAsNoRecord() {
        val repo = PairedDeviceRepository(unreadable)

        assertTrue(repo.lookupDevice(PEER) is DeviceLookup.Unreadable)
        assertThrows(SecurityException::class.java) { repo.getDevice(PEER) }
        assertFalse("an unreadable store confirms no peer", repo.isDeviceKnown(PEER))
        assertEquals(emptyList<PairedDeviceData>(), repo.getAllDevices())
    }

    @Test
    fun aReadableStoreWithoutThePeerIsNotPaired() {
        val empty = mockk<SharedPreferences>(relaxed = true).also {
            every { it.getString(any(), any()) } returns null
        }

        assertEquals(DeviceLookup.NotPaired, PairedDeviceRepository(empty).lookupDevice(PEER))
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

package com.automatethethings.xkey.settings

import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * A paired-device store whose encrypted prefs cannot be read (the keystore
 * is unavailable) reads as empty: the failure never escapes into a caller
 * such as an audit record.
 */
class PairedDeviceStoreReadTest {

    private val unreadable = mockk<SharedPreferences>().also {
        every { it.getString(any(), any()) } throws SecurityException("keystore unavailable")
    }

    @Test
    fun anUnreadableStoreReadsAsNoDevices() {
        val repo = PairedDeviceRepository(unreadable)

        assertEquals(emptyList<PairedDeviceData>(), repo.getAllDevices())
        assertNull(repo.getDevice(PEER))
        assertFalse(repo.isDeviceKnown(PEER))
    }

    private companion object {
        const val PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
    }
}

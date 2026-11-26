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

import android.app.Activity
import android.app.Application
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import androidx.appcompat.view.ContextThemeWrapper
import androidx.coordinatorlayout.widget.CoordinatorLayout
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File
import java.security.KeyStore

/**
 * #255 verify r3: a delete from the key list or the key detail screen whose
 * key store cannot be read threw [com.automatethethings.xkey.crypto.KeyPresenceUnreadableException]
 * out of the screen's coroutine (deleteUserKey caught only the internal-key
 * refusal), which crashed the app. Each screen now shows the refusal, deletes
 * nothing, and the detail screen stays open.
 *
 * The store is made unreadable the way a device can leave it: an older
 * build's software key record whose metadata cannot be parsed beside its
 * material, so no id's presence can be vouched for.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DeleteKeyScreenRefusalTest {

    private val dao = mockk<KeyPolicyDao>(relaxed = true) {
        coEvery { deletion(any()) } returns null
        coEvery { keyInstance(any()) } returns 1L
    }
    private val store = KeyPolicyStore(dao, object : KeyPolicyStore.Transactor {
        override suspend fun <T> run(block: suspend () -> T): T = block()
    })

    private val key = mockk<KeyEntity> {
        every { keyId } returns KEY_ID
        every { id } returns 1L
        every { isSystemKey } returns false
        every { keyType } returns "symmetric"
    }

    @Before
    fun setUp() {
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun theKeyListShowsARefusalForAnUnreadableStore() {
        val activity = Robolectric.buildActivity(KeyManagementActivity::class.java).get()
        val shown = screen(activity, "rootLayout", FrameLayout(themed(activity)))

        val failure = delete(activity, KeyManagementActivity::class.java)

        assertNull("the key list's delete threw: ${failure?.cause ?: failure}", failure)
        assertEquals(listOf(activity.getString(R.string.key_store_unreadable)), texts(shown))
        coVerify(exactly = 0) { dao.deleteKey(any()) }
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
    }

    @Test
    fun theKeyDetailScreenShowsARefusalAndStaysOpen() {
        val activity = Robolectric.buildActivity(KeyDetailActivity::class.java).get()
        val shown = screen(activity, "coordinatorLayout", CoordinatorLayout(themed(activity)))

        val failure = delete(activity, KeyDetailActivity::class.java)

        assertNull("the key detail screen's delete threw: ${failure?.cause ?: failure}", failure)
        assertEquals(listOf(activity.getString(R.string.key_store_unreadable)), texts(shown))
        assertFalse("a refused delete closed the key's screen", activity.isFinishing)
        coVerify(exactly = 0) { dao.deleteKey(any()) }
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
    }

    /** The screen's store is [store], its root [layout], its key store unreadable. */
    private fun <V : ViewGroup> screen(activity: Activity, root: String, layout: V): V {
        field(activity.javaClass, "keyPolicyStore\$delegate").set(activity, lazyOf(store))
        field(activity.javaClass, root).set(activity, layout)
        val dir = File(activity.filesDir, "software_keys").apply { mkdirs() }
        File(dir, "legacy.meta").writeText("{not json")
        File(dir, "legacy.key").writeBytes(ByteArray(4))
        return layout
    }

    private fun delete(activity: Activity, type: Class<*>): Throwable? {
        val delete = type.getDeclaredMethod("deleteKey", KeyEntity::class.java).apply { isAccessible = true }
        val failure = runCatching { delete.invoke(activity, key) }.exceptionOrNull()
        repeat(5) { shadowOf(Looper.getMainLooper()).idle() }
        return failure
    }

    private fun themed(activity: Activity) =
        ContextThemeWrapper(activity, com.google.android.material.R.style.Theme_MaterialComponents_DayNight)

    private fun texts(view: View): List<String> = when (view) {
        is TextView -> listOfNotNull(view.text?.toString()?.takeIf { it.isNotEmpty() })
        is ViewGroup -> (0 until view.childCount).flatMap { texts(view.getChildAt(it)) }
        else -> emptyList()
    }

    private fun field(type: Class<*>, name: String) =
        type.getDeclaredField(name).apply { isAccessible = true }

    private companion object {
        const val KEY_ID = "screen-key"
    }
}

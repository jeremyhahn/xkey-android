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

import com.automatethethings.xkey.storage.InternalKeyException
import com.automatethethings.xkey.storage.KeyMaterial
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.KeyStoreSyncManager
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The app's own Keystore keys are never offered as deletable user keys, and
 * a delete of one is refused without a crash (#255 review): the sync lists
 * every alias outside a user key's namespace as a system key, and every
 * delete screen deletes through [deleteUserKey], which turns the store's
 * [InternalKeyException] refusal into [UserKeyDelete.PROTECTED].
 */
class UserKeyDeleteTest {

    private val dao = mockk<KeyPolicyDao>(relaxed = true)
    private val store = KeyPolicyStore(dao, object : KeyPolicyStore.Transactor {
        override suspend fun <T> run(block: suspend () -> T): T = block()
    })

    private fun key(keyId: String, system: Boolean = false) = mockk<KeyEntity> {
        every { this@mockk.keyId } returns keyId
        every { id } returns 1L
        every { isSystemKey } returns system
    }

    /** Refuses as the app's deleter does for a key whose material is internal. */
    private val internal = mockk<KeyMaterial>(relaxed = true) {
        coEvery { generation(any(), any()) } answers { throw InternalKeyException(firstArg<KeyPolicyStore.KeyMaterialHeld>().keyId) }
    }

    @Test
    fun anInternalKeyDeleteIsRefusedWithNothingDeleted() = runTest {
        coEvery { dao.keyInstance(any()) } returns 1L

        assertEquals(UserKeyDelete.PROTECTED, deleteUserKey(key("xkey_seal_store_key"), store, internal))
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
        coVerify(exactly = 0) { dao.deleteKey(any()) }
    }

    @Test
    fun aSystemKeyIsRefusedBeforeTheStore() = runTest {
        assertEquals(UserKeyDelete.PROTECTED, deleteUserKey(key("xkey_password_encryption_key", system = true), store, internal))
        coVerify(exactly = 0) { internal.generation(any(), any()) }
        coVerify(exactly = 0) { dao.keyInstance(any()) }
    }

    @Test
    fun theAppsOwnAliasesAreProtectedAndUserKeysAreNot() {
        for (alias in listOf("xkey_seal_store_key", "xkey_password_encryption_key", "xkey_root_ca", "_androidx_security_master_key_", "other")) {
            assertTrue("$alias listed as a deletable user key", KeyStoreSyncManager.isProtectedAlias(alias))
        }
        for (alias in listOf("xkey_key_k", "xkey_credential_c")) {
            assertFalse("$alias listed as a system key", KeyStoreSyncManager.isProtectedAlias(alias))
        }
    }

    /** Bypass guard: no screen deletes a key around [deleteUserKey]. */
    @Test
    fun everyUiKeyDeleteGoesThroughDeleteUserKey() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val calls = File(root, "com/automatethethings/xkey/ui").walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeySharingPeers.kt" }
            .flatMap { file ->
                file.readLines().mapIndexedNotNull { i, line ->
                    if ("forgetKey(" in line.substringBefore("//")) "${file.name}:${i + 1}" else null
                }
            }
            .toList()
        assertEquals("a UI key delete outside deleteUserKey", 1, calls.size)
        val helper = File(root, "com/automatethethings/xkey/ui/KeyManagementActivity.kt").readText()
            .substringAfter("internal suspend fun deleteUserKey(")
        assertTrue("forgetKey(" in helper.substringBefore("\n}"))
    }
}

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

import com.automatethethings.xkey.storage.KeyMaterial
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A passkey deleted from the Passkeys list or its detail screen is deleted
 * as every other user key is: through [deleteUserKey] and
 * [KeyPolicyStore.deleteKey], which records a key_deletions tombstone in the
 * row delete's transaction and deletes the material, and then its
 * credential_metadata row. Without the tombstone and the metadata row
 * delete, the next key sync copies the passkey back into the keys table and
 * the credential provider keeps offering it.
 */
class PasskeyDeleteTombstoneTest {

    private var inTransaction = false
    private val putDeletionInTransaction = mutableListOf<Boolean>()

    private val dao = mockk<KeyPolicyDao>(relaxed = true) {
        // No earlier delete of any id is owed.
        coEvery { deletion(any()) } returns null
        coEvery { keyInstance(any()) } returns 1L
        coEvery { deleteKey(any()) } returns 1
        coEvery { putDeletion(any()) } answers { putDeletionInTransaction += inTransaction }
    }
    private val store = KeyPolicyStore(dao, object : KeyPolicyStore.Transactor {
        override suspend fun <T> run(block: suspend () -> T): T {
            inTransaction = true
            try {
                return block()
            } finally {
                inTransaction = false
            }
        }
    })
    private val credentials = mockk<CredentialMetadataDao>(relaxed = true)

    private val material = mockk<KeyMaterial>(relaxed = true) {
        coEvery { generation(any(), any()) } returns "g"
        coEvery { generation(any(), any(), any()) } returns "g"
        coEvery { delete(any(), any()) } returns true
    }

    private fun passkey(keyId: String = "p") = mockk<KeyEntity> {
        every { this@mockk.keyId } returns keyId
        every { id } returns 1L
        every { isSystemKey } returns false
    }

    @Test
    fun aPasskeyDeleteRecordsATombstoneAndDeletesItsMaterialAndCredentialRow() = runTest {
        val outcome = deletePasskey(passkey(), store, material, credentials)

        assertEquals(UserKeyDelete.DELETED, outcome)
        coVerify(exactly = 1) { dao.putDeletion(match<KeyDeletionEntity> { it.keyId == "p" }) }
        assertEquals("the tombstone was not written in the row delete's transaction", listOf(true), putDeletionInTransaction)
        coVerifyOrder {
            dao.putDeletion(match<KeyDeletionEntity> { it.keyId == "p" })
            dao.deleteKey("p")
        }
        coVerify(exactly = 1) { material.delete(any(), match { it.keyId == "p" }) }
        coVerify(exactly = 1) { credentials.deleteByCredentialId("p") }
    }

    @Test
    fun aPasskeyAlreadyGoneKeepsItsCredentialRow() = runTest {
        // The row was deleted or generated again meanwhile.
        coEvery { dao.keyInstance(any()) } returns 2L

        assertEquals(UserKeyDelete.GONE, deletePasskey(passkey(), store, material, credentials))
        coVerify { dao.keyInstance("p") }
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
        coVerify(exactly = 0) { credentials.deleteByCredentialId(any()) }
    }

    @Test
    fun aRefusedPasskeyDeleteKeepsItsCredentialRow() = runTest {
        val failing = mockk<KeyMaterial>(relaxed = true) {
            coEvery { generation(any(), any()) } throws java.security.KeyStoreException("keystore")
            coEvery { generation(any(), any(), any()) } throws java.security.KeyStoreException("keystore")
        }

        val outcome = deletePasskey(passkey(), store, failing, credentials)

        assertTrue("a refused delete reported as $outcome", outcome is UserKeyDelete.Refused)
        assertEquals(com.automatethethings.xkey.R.string.key_delete_failed, outcome.refusal)
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
        coVerify(exactly = 0) { credentials.deleteByCredentialId(any()) }
    }

    @Test
    fun aBlockedPasskeyDeleteKeepsItsCredentialRow() = runTest {
        val tables = com.automatethethings.xkey.storage.FakeKeyPolicyTables()
        val store = tables.store()
        val instance = tables.addKey("p", com.automatethethings.xkey.storage.entity.SharingPolicyType.SELECTED_PEERS)
        // A same-id key's material delete is still owed and cannot be settled.
        assertEquals(
            KeyPolicyStore.MaterialDelete.DELETED,
            store.deleteMaterial("p", owing("credential"), besideRow = instance)
        )

        val outcome = deletePasskey(tables.key("p")!!, store, owing("passkey"), credentials)

        assertEquals(UserKeyDelete.PENDING, outcome)
        assertEquals("the passkey's row was deleted", instance, store.instance("p"))
        coVerify(exactly = 0) { credentials.deleteByCredentialId(any()) }
    }

    /** A [KeyMaterial] of generation [generation] whose every delete fails, so its tombstone stays owed. */
    private fun owing(generation: String): KeyMaterial = object : KeyMaterial {
        override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?): String = generation

        override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean = false
    }

    /**
     * Bypass guard: both passkey screens delete through [deletePasskey] and
     * show its refusal, [deletePasskey] deletes through [deleteUserKey], and
     * no screen deletes a key row or a credential_metadata row directly.
     */
    @Test
    fun everyPasskeyDeleteGoesThroughDeletePasskey() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val ui = File(root, "com/automatethethings/xkey/ui")
        for (screen in listOf("PasskeysActivity.kt", "PasskeyDetailActivity.kt")) {
            val body = File(ui, screen).readText()
                .substringAfter("private fun showDeleteConfirmation(key: KeyEntity)").substringBefore("\n    }\n")
            assertTrue("$screen deletes a passkey around deletePasskey", "deletePasskey(" in body)
            assertTrue("$screen does not show a refused delete", "outcome.refusal" in body)
        }
        val helper = File(ui, "PasskeyDelete.kt").readText()
            .substringAfter("internal suspend fun deletePasskey(").substringBefore("\n}")
        assertTrue("deletePasskey deletes around deleteUserKey", "deleteUserKey(" in helper)

        val raw = Regex("""\b(deleteByKeyId|deleteRowByKeyId|deleteMetadataRowByCredentialId)\(""")
        val hits = ui.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file ->
                file.readLines().mapIndexedNotNull { i, line ->
                    val code = line.substringBefore("//")
                    val comment = code.trimStart().let { it.startsWith("*") || it.startsWith("/*") }
                    if (!comment && raw.containsMatchIn(code)) "${file.name}:${i + 1}" else null
                }
            }
            .toList()
        assertEquals("a UI key delete around KeyPolicyStore.deleteKey", emptyList<String>(), hits)
    }
}

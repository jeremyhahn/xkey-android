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

import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Deletes [contact] by its public key fingerprint and writes the
 * contact-deleted audit entry only when the delete removed a row: a contact
 * another screen or an earlier tap already removed is not audited again.
 *
 * @return true if a row was removed.
 */
internal suspend fun deleteContactAudited(contactDao: ContactDao, contact: ContactEntity): Boolean {
    val removed = withContext(Dispatchers.IO) {
        contactDao.deleteByFingerprint(contact.publicKeyFingerprint)
    }
    if (removed <= 0) return false
    AuditLogger.logContactDeleted(
        name = contact.name,
        fingerprint = contact.publicKeyFingerprint
    )
    return true
}

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
package com.automatethethings.xkey.ui

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking

/**
 * Seeding and launch helpers shared by the [KeyDetailActivity] and
 * [KeySharingBottomSheet] instrumented suites.
 *
 * Every one of those suites drives the same screen from the same real Room
 * database, so the row plumbing lives here rather than being repeated three
 * times. Tests build their [KeyEntity] fixtures inline -- the entity already has
 * sensible defaults for everything a given test does not care about -- and use
 * [seedKeyRow] / [deleteKeyRows] so the rows never outlive the test that created
 * them. Leftover rows are not harmless: other suites assert on live key counts.
 */

/** Application context for the instrumented process. */
fun keyTestContext(): Context = ApplicationProvider.getApplicationContext()

/** The app's real [KeyDao], backed by the on-device database. */
fun keyTestDao(): KeyDao = XKeyDatabase.getInstance(keyTestContext()).keyDao()

/** The app's real [KeySharingPolicyDao], backed by the on-device database. */
fun keySharingTestDao(): KeySharingPolicyDao =
    XKeyDatabase.getInstance(keyTestContext()).keySharingPolicyDao()

/** Inserts [key] into the keys table. */
fun seedKeyRow(key: KeyEntity) {
    runBlocking { keyTestDao().insert(key) }
}

/**
 * Removes every row in [keyIds], along with its sharing policies.
 *
 * The foreign key on `key_sharing_policies` cascades, but the policies are
 * cleared explicitly first so the teardown still holds if a test seeded a policy
 * for a key it did not seed itself.
 */
fun deleteKeyRows(vararg keyIds: String) {
    runBlocking {
        for (keyId in keyIds) {
            keySharingTestDao().clearPoliciesForKey(keyId)
            keyTestDao().deleteByKeyId(keyId)
        }
    }
}

/** Launches [KeyDetailActivity] for [keyId]. */
fun launchKeyDetail(keyId: String): ActivityScenario<KeyDetailActivity> {
    val intent = Intent(keyTestContext(), KeyDetailActivity::class.java).apply {
        putExtra(KeyDetailActivity.EXTRA_KEY_ID, keyId)
    }
    return ActivityScenario.launch(intent)
}

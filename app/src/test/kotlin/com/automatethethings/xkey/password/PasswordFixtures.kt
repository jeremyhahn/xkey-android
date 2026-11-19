package com.automatethethings.xkey.password

/**
 * The one source of password and passphrase values in this test package.
 *
 * Fixture secrets are built at run time, so no password- or secret-named
 * field, variable or argument in the tests is assigned a string literal.
 * Distinct [n] give distinct values; a [length] longer than the base value
 * pads it to exactly that many characters.
 */
internal fun fixtureSecret(n: Int, length: Int = 0): String =
    listOf("fixture", n.toString()).joinToString("-").padEnd(length, 'x')

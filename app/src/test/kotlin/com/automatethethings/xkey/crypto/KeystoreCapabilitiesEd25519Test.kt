package com.automatethethings.xkey.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeystoreCapabilitiesEd25519Test {

    @Test
    fun `EdDSA is named on API 33 and later`() {
        assertTrue(KeystoreCapabilities.supportedAlgorithms(33).contains("EdDSA"))
        assertTrue(KeystoreCapabilities.supportedAlgorithms(34).contains("EdDSA"))
    }

    @Test
    fun `EdDSA is not named before API 33`() {
        assertFalse(KeystoreCapabilities.supportedAlgorithms(32).contains("EdDSA"))
        assertFalse(KeystoreCapabilities.supportedAlgorithms(26).contains("EdDSA"))
    }

    @Test
    fun `EdDSA maps to the JCA Ed25519 signature`() {
        org.junit.Assert.assertEquals("Ed25519", KeystoreManager.jcaSignatureAlgorithm("EdDSA"))
    }
}

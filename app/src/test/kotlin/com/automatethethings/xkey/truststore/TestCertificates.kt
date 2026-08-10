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
package com.automatethethings.xkey.truststore

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Fixed X.509 test fixtures for the trust-store and CA unit tests.
 *
 * Every certificate here is a real, pre-generated NIST P-256 / SHA-256 certificate,
 * so the JCA can parse, chain-build and signature-verify them without any Android
 * framework or Android Keystore support. Using frozen PEM (rather than generating
 * key material at test time) keeps the tests deterministic and lets negative cases
 * assert on exact subject/issuer values.
 *
 * Topology:
 * ```
 *   xKey Test Root CA  (self-signed, pathlen 1)
 *     |- device-a.xkey.test              [LEAF_A]                  valid until 2124
 *     |- expired-device.xkey.test        [EXPIRED_LEAF_A]          expired in 2021
 *     `- xKey Test Intermediate CA       [INTERMEDIATE_A]
 *          `- device-c.xkey.test         [LEAF_VIA_INTERMEDIATE]
 *
 *   Android Test Root CA    -> device-b.xkey.test    [LEAF_B]   (trust level "android-ca")
 *   xKey StrongBox Root CA  -> device-sb.xkey.test   [LEAF_C]   (trust level "hardware-backed")
 *   xKey TEE Root CA        -> device-tee.xkey.test  [LEAF_D]   (trust level "tee-backed")
 * ```
 *
 * The B/C/D roots are unrelated to root A, so any leaf from one hierarchy is a
 * genuinely untrusted certificate when only another hierarchy's root is imported.
 */
internal object TestCertificates {

    // -------------------------------------------------------------------------
    // Hierarchy A: "xKey Test Root CA"
    // -------------------------------------------------------------------------

    const val ROOT_CA_A_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBwjCCAWmgAwIBAgIUFbGe1x87FyWohyUN5uwTSuScbt0wCgYIKoZIzj0EAwIw\n" +
        "PTELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEaMBgGA1UEAwwReEtl\n" +
        "eSBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAwMDBa\n" +
        "MD0xCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAl4S2V5IFRlc3QxGjAYBgNVBAMMEXhL\n" +
        "ZXkgVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERd3C9YFc\n" +
        "k7tygj8w6b2Xul+SXkxnwxdVMdXWP6vg+Y6ScNdBGnxfzzMrz3bgoD8/QHyE4Vzm\n" +
        "KauZNGiJ9RNUcqNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMC\n" +
        "AYYwHQYDVR0OBBYEFNUbNo2DZjEhJfFOEQxML859XBBjMAoGCCqGSM49BAMCA0cA\n" +
        "MEQCIEJGVBiZ4YQAjUT82QdLz731zuMpVdAiago/AgRIZUSRAiBA+NxEAjyvZrCD\n" +
        "flBO3FmtVy97THtOmXPzB28YqpMRgQ==\n" +
        "-----END CERTIFICATE-----\n"

    const val LEAF_A_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBvTCCAWSgAwIBAgIUXAfwhcDUyO9QLK0wU7zcb6zw9aEwCgYIKoZIzj0EAwIw\n" +
        "PTELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEaMBgGA1UEAwwReEtl\n" +
        "eSBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAwMDBa\n" +
        "MD4xCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAl4S2V5IFRlc3QxGzAZBgNVBAMMEmRl\n" +
        "dmljZS1hLnhrZXkudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJbzJl7Z\n" +
        "kPbR4aJPqgVAEp4iqMVFPaw79cz/Q5vc+6gcbYqbAl9ISYLeJUMos7xaI2cT4gPf\n" +
        "1IMhaLqvISXl9MqjPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0G\n" +
        "A1UdDgQWBBQBspL5h3Q8WzVTWuO6rhvXEQScmzAKBggqhkjOPQQDAgNHADBEAiBd\n" +
        "f7n7dvfi6S/YJwAIAmb7TmMlY9n9r8bM5gHSwAbgKAIgVLy0QPirVch1t5jEbQ9e\n" +
        "N/P06bsWlYMp1GsS9pJLfqQ=\n" +
        "-----END CERTIFICATE-----\n"

    const val EXPIRED_LEAF_A_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBwjCCAWigAwIBAgIUOdcFcaSS5PUU5psEbzsQR+U7zhUwCgYIKoZIzj0EAwIw\n" +
        "PTELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEaMBgGA1UEAwwReEtl\n" +
        "eSBUZXN0IFJvb3QgQ0EwHhcNMjAwMTAxMDAwMDAwWhcNMjEwMTAxMDAwMDAwWjBE\n" +
        "MQswCQYDVQQGEwJVUzESMBAGA1UECgwJeEtleSBUZXN0MSEwHwYDVQQDDBhleHBp\n" +
        "cmVkLWRldmljZS54a2V5LnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATU\n" +
        "OwW3k3igeHEaiHaNSiQsYfu2iUVKyH7+reVBo5gaHfgUhXO9B8hSmhEX1ML4Dphj\n" +
        "Qh3MJ1dLKnqfwwIMhC2Voz8wPTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIH\n" +
        "gDAdBgNVHQ4EFgQUPJ3MJVm0XMs/wRvovrJH+QFK/9MwCgYIKoZIzj0EAwIDSAAw\n" +
        "RQIhANXcgU3ZodqFpNMPzMFIoKbIY0olx9mVw2qkQWEZrlrlAiABRzomxp6NKGG7\n" +
        "JajcINWm0b75VCIYpqE3+KKnnraqzw==\n" +
        "-----END CERTIFICATE-----\n"

    const val INTERMEDIATE_A_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBzDCCAXGgAwIBAgIUDJ1RMh1tHvnCMf1EDgpweNh6dDswCgYIKoZIzj0EAwIw\n" +
        "PTELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEaMBgGA1UEAwwReEtl\n" +
        "eSBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAwMDBa\n" +
        "MEUxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAl4S2V5IFRlc3QxIjAgBgNVBAMMGXhL\n" +
        "ZXkgVGVzdCBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
        "AAScY4f3G7raSu5THus4mlZqilry9DA+4lMytXdaSK75r2iCpmz2XXVCXUSZ1DWl\n" +
        "1/7/rZJB+pdN2HR+9acDkuLyo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud\n" +
        "DwEB/wQEAwIBhjAdBgNVHQ4EFgQURirJCdngdH40zPBFOjFiKOPxL9owCgYIKoZI\n" +
        "zj0EAwIDSQAwRgIhAJLd4eyFVuH+7TniK+Pcndco+0glTLFskHgxRwzj3xTEAiEA\n" +
        "6xQRMuYvZ7fEPdNCZID4yCw/XfEOT4jgI9jVVUYqfzo=\n" +
        "-----END CERTIFICATE-----\n"

    const val LEAF_VIA_INTERMEDIATE_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBxTCCAWygAwIBAgIUZ+7ym4sSgf4/zkR54XNm39O2BSMwCgYIKoZIzj0EAwIw\n" +
        "RTELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEiMCAGA1UEAwwZeEtl\n" +
        "eSBUZXN0IEludGVybWVkaWF0ZSBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTI0MDEw\n" +
        "MTAwMDAwMFowPjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEbMBkG\n" +
        "A1UEAwwSZGV2aWNlLWMueGtleS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n" +
        "QgAE90uS9bd1PQbbM9KLkPWjNM3dHNk27bAji8qMNqAKykOtwrP0BjrGB4VZZspa\n" +
        "sJ/nQsN3PqS4aVFq/oF9lEC/1qM/MD0wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E\n" +
        "BAMCB4AwHQYDVR0OBBYEFCQjy9rviDID4m3Dxwk8yhtwaTRMMAoGCCqGSM49BAMC\n" +
        "A0cAMEQCIB/NkA+8G8eadbgwxu86LKC1Jg2HjwKwhBDirlrhpRLpAiAlHxIokhSi\n" +
        "G+eJhgvjYwHgMU0JSlTiu9keXeRh4KcRpQ==\n" +
        "-----END CERTIFICATE-----\n"

    // -------------------------------------------------------------------------
    // Unrelated hierarchies (used for broken-chain and trust-level assertions)
    // -------------------------------------------------------------------------

    const val ROOT_CA_B_ANDROID_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIByDCCAW+gAwIBAgIUCdwzMrENCFJCbXEogonOmQlfiLEwCgYIKoZIzj0EAwIw\n" +
        "QDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEdMBsGA1UEAwwUQW5k\n" +
        "cm9pZCBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAw\n" +
        "MDBaMEAxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAl4S2V5IFRlc3QxHTAbBgNVBAMM\n" +
        "FEFuZHJvaWQgVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n" +
        "qmTrYHLYhdnh7D+edOxfJRgGftqAm5h7hhz41Poj0Svz9JRCFo2Zo97/24JOo69J\n" +
        "hCjDbNOJtlqUQtwyXplKqqNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8B\n" +
        "Af8EBAMCAYYwHQYDVR0OBBYEFEsIAZLlRoiowzZCu+B6RiLE1jKgMAoGCCqGSM49\n" +
        "BAMCA0cAMEQCIGC+hgeGOVSSzBj7VeQRBY6xEA2tX6+c1gc+kREcgkLUAiAjdG3B\n" +
        "SSXyCXWS8/XIg9vE7c0FMdIKk9xslHUipdiycg==\n" +
        "-----END CERTIFICATE-----\n"

    const val LEAF_B_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBwjCCAWegAwIBAgIUER4OMzmKEIwwJ3iitQChicyVNb4wCgYIKoZIzj0EAwIw\n" +
        "QDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEdMBsGA1UEAwwUQW5k\n" +
        "cm9pZCBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAw\n" +
        "MDBaMD4xCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAl4S2V5IFRlc3QxGzAZBgNVBAMM\n" +
        "EmRldmljZS1iLnhrZXkudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIGH\n" +
        "pldtdOLONzDcsJIN+pOKQN0yQosfykCG3QijhnhCugs2MyyJlVU0vAoOebXCEaTF\n" +
        "CGPbXfH0AR5f0EVzSI2jPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA\n" +
        "MB0GA1UdDgQWBBQWAmBNya7Kw/P60mQ1G3V4c+kIfTAKBggqhkjOPQQDAgNJADBG\n" +
        "AiEAwGd8id0KYLoNgCzRb3GsxpG82GwJQ2MQhFI5+1Hh7iUCIQDe2o8RJtW8Oh02\n" +
        "VUtq+XVtDobJmFfgHK2k7G+V32lyYA==\n" +
        "-----END CERTIFICATE-----\n"

    const val ROOT_CA_C_STRONGBOX_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBzDCCAXOgAwIBAgIUECE72FxLTKjfKefodqBJSESiBzIwCgYIKoZIzj0EAwIw\n" +
        "QjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEfMB0GA1UEAwwWeEtl\n" +
        "eSBTdHJvbmdCb3ggUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAw\n" +
        "MDAwMFowQjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEfMB0GA1UE\n" +
        "AwwWeEtleSBTdHJvbmdCb3ggUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n" +
        "A0IABFGnprWDUCngQidymqAjTva5TOKYbp5Ih+3rtH4PF22K7gzjY7lTiFq7TX+I\n" +
        "0vEytZrTiAv9V6VJoxcvT+uu5UajRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYD\n" +
        "VR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTdMB498xN2hcUUJ8ETCmIV+6qNYjAKBggq\n" +
        "hkjOPQQDAgNHADBEAiACI2Q0OcBDn0On8BJmlRkn7SG8UWXhcxOvor+AOuGM0gIg\n" +
        "ZubjgUxMqaevbs7ytUF8OZCsz8DD1irptLJTm6NUUL4=\n" +
        "-----END CERTIFICATE-----\n"

    const val LEAF_C_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBxTCCAWqgAwIBAgIUW121fjySFONsVvQbuL5MNDlKBX8wCgYIKoZIzj0EAwIw\n" +
        "QjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEfMB0GA1UEAwwWeEtl\n" +
        "eSBTdHJvbmdCb3ggUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAw\n" +
        "MDAwMFowPzELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEcMBoGA1UE\n" +
        "AwwTZGV2aWNlLXNiLnhrZXkudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n" +
        "BK/DGsnzftVbhv6lLbO4KJ4FGLMo1ZU43mG1udGxEtsYYq71mQPURC6ZHNH7wOIY\n" +
        "Ske29q1Ca0Yox0Ro5iRp356jPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD\n" +
        "AgeAMB0GA1UdDgQWBBScJNo7UixMpEYhYKcrlKGhEPmqBzAKBggqhkjOPQQDAgNJ\n" +
        "ADBGAiEAwuhC/tH2H/8V/isg7M/dqn6Q4pPTVMyLBFJiprKlJRMCIQDKxQvNTHEb\n" +
        "TCTaQJUAqi9Iehbv5W6lI4OBcvlKJWMlgA==\n" +
        "-----END CERTIFICATE-----\n"

    const val ROOT_CA_D_TEE_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBwTCCAWegAwIBAgIUEsdlUHGpGYaHlVghjZ9HyTNA3tcwCgYIKoZIzj0EAwIw\n" +
        "PDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEZMBcGA1UEAwwQeEtl\n" +
        "eSBURUUgUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAwMDAwMFow\n" +
        "PDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEZMBcGA1UEAwwQeEtl\n" +
        "eSBURUUgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCkCgIhwUIyF\n" +
        "rhwmt4178qEXbZIHioJttsQC0lEm4ZWuRQIpJJDys6V7JYSlVhNH9nKXzuP82WGv\n" +
        "To9FhlTRbLSjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgGG\n" +
        "MB0GA1UdDgQWBBRdRecqtZp1Hng9tA9foAaWaztiHTAKBggqhkjOPQQDAgNIADBF\n" +
        "AiAKPd0KB6GMQU6E0m68VdUjku1z9LsodjhGAFBbMVJXoQIhAPaIavL/vaBULlxW\n" +
        "HYczQv/xA2S+Zeh0yI+srBKzh+CZ\n" +
        "-----END CERTIFICATE-----\n"

    const val LEAF_D_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBwDCCAWWgAwIBAgIUOkviP/2HaYCPsckqHIcMGjnMZkgwCgYIKoZIzj0EAwIw\n" +
        "PDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEZMBcGA1UEAwwQeEtl\n" +
        "eSBURUUgUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAwMDAwMFow\n" +
        "QDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCXhLZXkgVGVzdDEdMBsGA1UEAwwUZGV2\n" +
        "aWNlLXRlZS54a2V5LnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATvYWwA\n" +
        "nfYeAPmL7mJI6qQw2ex05RFE3oPhulfLIykyX81dXkfIUMlzMDSsN2+1f2dSRgQa\n" +
        "Uvpm/0e1LpBXBV35oz8wPTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAd\n" +
        "BgNVHQ4EFgQU7DZ/Lxx0aKL/o5C+88xMK3Hqn48wCgYIKoZIzj0EAwIDSQAwRgIh\n" +
        "ANUGMyF/v1HZOKKccIUChvI7J+XizyNS0ifdqIVQijTvAiEA0FODs8O1W9007Lq6\n" +
        "R2SjuFOFD+o8wUB+4uEt1sqkqGs=\n" +
        "-----END CERTIFICATE-----\n"

    /** A syntactically valid PEM that is NOT a certificate (an EC SubjectPublicKeyInfo). */
    const val NOT_A_CERTIFICATE_PEM: String =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs1hmg+TMXX+fJfQFka7aFMz8ZHmp\n" +
        "J29tW2gmOQoYXa77PW8Bis6R8SpNIrDOmhrQhj/1iHDOJK0OXDavCfsVIA==\n" +
        "-----END PUBLIC KEY-----\n"

    // Expected subject/issuer values, asserted against rather than derived at runtime.
    const val ROOT_A_CN = "CN=xKey Test Root CA"
    const val LEAF_A_CN = "CN=device-a.xkey.test"
    const val INTERMEDIATE_A_CN = "CN=xKey Test Intermediate CA"
    const val LEAF_VIA_INTERMEDIATE_CN = "CN=device-c.xkey.test"
    const val EXPIRED_LEAF_A_CN = "CN=expired-device.xkey.test"

    /** notAfter of [EXPIRED_LEAF_A_PEM]: 2021-01-01T00:00:00Z. */
    const val EXPIRED_LEAF_A_NOT_AFTER_MILLIS = 1609459200000L

    /** notAfter of every long-lived fixture: 2124-01-01T00:00:00Z. */
    const val LONG_LIVED_NOT_AFTER_MILLIS = 4859740800000L

    private val factory: CertificateFactory get() = CertificateFactory.getInstance("X.509")

    /** Strip the PEM armour and return the raw DER bytes. */
    fun der(pem: String): ByteArray {
        val body = pem
            .lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
            .trim()
        return Base64.getDecoder().decode(body)
    }

    /** Parse a PEM fixture into an [X509Certificate]. */
    fun cert(pem: String): X509Certificate =
        factory.generateCertificate(ByteArrayInputStream(der(pem))) as X509Certificate

    /**
     * SHA-256 hex digest, computed here so the trust-store fingerprint assertions
     * are independent of the production implementation.
     */
    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { String.format("%02x", it) }

    /** SHA-256 fingerprint of a PEM fixture's DER encoding. */
    fun fingerprint(pem: String): String = sha256Hex(der(pem))
}

# Certificate authority: engineering notes

## Certificate validity

A certificate the CA signs never outlives the certificate that signs it,
and a CA certificate that is expired or not yet valid signs nothing.

The rule lives in one pure function file,
`app/src/main/kotlin/com/automatethethings/xkey/ca/CertificateValidity.kt`:

- `validityFor(now, validityDays, issuerNotBefore, issuerNotAfter)` takes a
  profile's validity in days (24-hour days from `now`);
- `validityUntil(now, requestedNotAfter, issuerNotBefore, issuerNotAfter)`
  takes a requested end date.

Both return notBefore = `now` and notAfter = the earlier of the requested
end and the issuer's notAfter (the clamp). They refuse:

| Case | Exception | Message names |
|------|-----------|---------------|
| `validityDays <= 0` | `IllegalArgumentException` | the days given |
| issuer notAfter before `now` | `IllegalStateException` | the issuer's notAfter |
| issuer notBefore after `now` | `IllegalStateException` | the issuer's notBefore |

Callers in `AndroidCA`:

- `issueForPublicKey`, which every issuance path goes through
  (`issueCertificate`, `issueIDevIDCertificate`, `signCSR`,
  `issueCertificateWithProfile`), checks against the signing certificate
  before anything is built, signed or stored, so a refusal stores nothing
  and logs no issuance.
- `generateIntermediateCertificate` checks the intermediate's five calendar
  years against the root.

Not covered by the rule: the root's own validity, the CRL's validity, and
`SSHCertificateAuthority`.

Tests: `app/src/test/kotlin/com/automatethethings/xkey/ca/CertificateValidityTest.kt`
(fixed dates, no clock).

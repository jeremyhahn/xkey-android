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

## Revocation

The CRL `AndroidCA.generateCRL()` signs is a direct CRL (RFC 5280 section
5.1): it lists only the revoked certificates the current intermediate
signed. The `certificates` table holds more than that: the intermediate's
own row (signed by the root), and, after `reset()` and a fresh initialise,
every certificate the old intermediate signed, often under the same name.

`revokedIssuedBy(rows, issuer)` in `AndroidCA.kt` keeps a revoked row only
when its stored certificate (`certificatePEM`) parses, its issuer name equals
the intermediate's subject (DER compare), and its signature verifies with the
intermediate's public key. The signature is what tells two intermediates of
the same name apart; the authority key identifier is optional in a
certificate, the signature is not. A row whose certificate does not parse is
left out, with a warning in the log.

A revocation is final. `CertificateDao.revoke` updates only a row with
`revoked = 0` and returns the number of rows it changed, so a second
revocation keeps the first date and reason, from every caller (the
management screens call the DAO directly). `AndroidCA.revoke` returns `true`
when it revoked the certificate and `false` when it was already revoked; it
writes the audit entry only in the first case, and throws
`IllegalArgumentException` for an unknown serial.

Not covered: a CRL for an old intermediate's certificates, and a CRL signed
by the root for a revoked intermediate.

Tests: `app/src/test/kotlin/com/automatethethings/xkey/ca/AndroidCARevocationTest.kt`.

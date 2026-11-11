---
uid: upgradingToV5
---

# Upgrading from v4 to v5

v5 is a breaking release. Hashes you've already stored still verify, but the namespace and several method signatures have
changed, and passwords over 72 bytes are handled differently by default.

If you use ASP.NET Core Identity, also read [ASP.NET Core Identity in v5](xref:identityExtensionsAdoption). That package is
new in v5.

## Checklist

1. Update `BCrypt.Net-Next` to v5. If you use `BCrypt.Net-Next.StrongName`, switch to `BCrypt.Net-Next`.
2. Replace `using BCrypt.Net;` with `using BCryptNet;`.
3. Decide how to handle passwords over 72 bytes (see [Long passwords](#long-passwords)). **Don't skip this.**
4. Replace `EnhancedHashPassword` / `EnhancedVerify` and the `enhancedEntropy` overloads with `BCryptExtendedV2`.
5. Replace `ValidateAndReplacePassword` with `ValidateAndUpgradeHash`.
6. Remove calls to `GenerateSalt` and `HashString`.

## Packages and target frameworks

The package is still `BCrypt.Net-Next`. The assembly is now strong-name signed, so the separate
`BCrypt.Net-Next.StrongName` package is no longer needed. Reference `BCrypt.Net-Next` instead.

v5 targets `netstandard2.0`, `netstandard2.1`, `net462`, `net472`, `net48`, `net8.0` and `net10.0`.

## Namespace

The namespace has changed from `BCrypt.Net` to `BCryptNet`, so it no longer clashes with the `BCrypt` class.

```csharp
// v4
using BCrypt.Net;
var hash = BCrypt.Net.BCrypt.HashPassword(password);

// v5
using BCryptNet;
var hash = BCrypt.HashPassword(password);
```

The exception types (`SaltParseException`, `BcryptAuthenticationException`, `HashInformationException`), `HashType` and
`HashInformation` have moved to `BCryptNet` as well.

## Existing hashes

You don't need to re-hash anything when you upgrade. Hash output hasn't changed:

- Plain hashes created by v4 `HashPassword` verify with `BCrypt.Verify`.
- Enhanced hashes created by v4 `EnhancedHashPassword` (or with `enhancedEntropy: true`) are Enhanced Entropy V2 hashes.
  They verify with `BCryptExtendedV2.Verify`, using the same `HashType` they were created with.
- Enhanced Entropy V1 (from v3.x and earlier, before the v4 fix) is not supported. Migrate those hashes with v4 first.

## Long passwords

bcrypt only uses the first 72 bytes of a password. **v4 silently ignored anything after that. v5 throws
`PasswordTooLongException` by default**, whether hashing or verifying, when the UTF-8 encoded password (including the
terminating NUL) is longer than 72 bytes.

If any of your users have passwords that long, verifying their v4 hashes in v5 throws instead of returning `true`.
`PasswordTooLongException` derives from `ArgumentException`, so existing `catch (ArgumentException)` blocks still catch it.

You have two options.

**Keep the v4 behaviour.** Pass `LongPasswordHandling.Truncate` when hashing and verifying:

```csharp
var truncate = new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate);

var hash = BCrypt.HashPassword(password, truncate);
var isValid = BCrypt.Verify(password, hash, truncate);
```

**Move users to a pre-hashed scheme.** [Enhanced Entropy](xref:enhancedEntropy) hashes the password before bcrypt, so the
whole password counts. You can migrate each user on their next login. Verify the old hash with truncation, then re-hash
with V2:

```csharp
var truncate = new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate);

// Throws BcryptAuthenticationException if the password is wrong
string newHash = BCryptExtendedV2.ValidateAndUpgradeHash(password, storedHash, HashType.None, password, truncate);
```

After migrating, verify with `BCryptExtendedV2.Verify`. Bcrypt hashes don't record whether they were pre-hashed, so you
need to track which users have been migrated, for example with a column, or by using the
[Identity hasher](xref:identityExtensionsAdoption), which tags its hashes.

## API changes

Optional settings (work factor, long-password handling, pre-hash algorithm) are now passed as a `BCryptOptions` value
instead of through separate overloads. `default(BCryptOptions)` means the library defaults: work factor 11, throw on long
passwords, SHA384 for V2.

### Hashing and verifying

| v4 | v5 |
| --- | --- |
| `BCrypt.HashPassword(pw)` | unchanged |
| `BCrypt.HashPassword(pw, workFactor)` | unchanged |
| `BCrypt.HashPassword(pw, salt)` | unchanged |
| `BCrypt.Verify(pw, hash)` | unchanged |
| `BCrypt.HashString(pw, workFactor)` | `BCrypt.HashPassword(pw, workFactor)` |
| `BCrypt.EnhancedHashPassword(pw)` | `BCryptExtendedV2.HashPassword(pw)` |
| `BCrypt.EnhancedHashPassword(pw, workFactor)` | `BCryptExtendedV2.HashPassword(pw, workFactor)` |
| `BCrypt.HashPassword(pw, workFactor, true)` | `BCryptExtendedV2.HashPassword(pw, workFactor)` |
| `BCrypt.EnhancedHashPassword(pw, workFactor, hashType)`<br/>`BCrypt.EnhancedHashPassword(pw, hashType, workFactor)` | `BCryptExtendedV2.HashPassword(pw, new BCryptOptions(workFactor, preHash: PreHash.Sha2(hashType)))` |
| `BCrypt.HashPassword(pw, salt, true, hashType)` | `BCryptExtendedV2.HashPassword(pw, salt, new BCryptOptions(preHash: PreHash.Sha2(hashType)))` |
| `BCrypt.EnhancedVerify(pw, hash)`<br/>`BCrypt.Verify(pw, hash, true)` | `BCryptExtendedV2.Verify(pw, hash)` |
| `BCrypt.EnhancedVerify(pw, hash, hashType)`<br/>`BCrypt.Verify(pw, hash, true, hashType)` | `BCryptExtendedV2.Verify(pw, hash, new BCryptOptions(preHash: PreHash.Sha2(hashType)))` |
| `BCrypt.PasswordNeedsRehash(hash, workFactor)` | unchanged |
| `BCrypt.InterrogateHash(hash)` | unchanged |
| `BCrypt.GenerateSalt()`<br/>`BCrypt.GenerateSalt(workFactor, revision)` | removed; use `HashPassword(pw, workFactor)` and let the library generate the salt |

`BCryptExtendedV2` defaults to SHA384, the same default as v4's enhanced methods. If you passed a `HashType` in v4, pass
the same one in v5.

### Validating and replacing a hash

`ValidateAndReplacePassword` is now `ValidateAndUpgradeHash`. As before, it throws `BcryptAuthenticationException` if the
current password doesn't match. It also keeps the current hash's work factor if it's higher than the one requested, unless
you pass `forceWorkFactor: true`.

| v4 | v5 |
| --- | --- |
| `BCrypt.ValidateAndReplacePassword(cur, hash, newPw)` | `BCrypt.ValidateAndUpgradeHash(cur, hash, newPw)` |
| `BCrypt.ValidateAndReplacePassword(cur, hash, newPw, workFactor, forceWorkFactor)` | `BCrypt.ValidateAndUpgradeHash(cur, hash, newPw, new BCryptOptions(workFactor), forceWorkFactor)` |
| `BCrypt.ValidateAndReplacePassword(cur, hash, true, oldType, newPw, true, newType, workFactor, forceWorkFactor)` (enhanced → enhanced) | `BCryptExtendedV2.ValidateAndUpgradeHash(cur, hash, oldType, newPw, new BCryptOptions(workFactor, preHash: PreHash.Sha2(newType)), forceWorkFactor)` |
| `BCrypt.ValidateAndReplacePassword(cur, hash, false, HashType.None, newPw, true, newType)` (plain → enhanced) | `BCryptExtendedV2.ValidateAndUpgradeHash(cur, hash, HashType.None, newPw, new BCryptOptions(preHash: PreHash.Sha2(newType)))` |
| `BCrypt.ValidateAndReplacePassword(cur, hash, true, oldType, newPw)` (enhanced → plain) | `BCrypt.ValidateAndUpgradeHash(cur, hash, PreHash.Sha2(oldType), newPw)` |

`BCrypt.ValidateAndUpgradeHash(cur, hash, currentPreHash, newPw, options, currentHmacKey, newHmacKey)` handles any
combination of schemes, including moving to Enhanced Entropy V3. See
[Changing scheme or rotating the HMAC key](xref:enhancedEntropy#changing-scheme-or-rotating-the-hmac-key).

## Stricter input validation

v5 rejects some inputs that v4 accepted:

- The work factor must be between 4 and 31. `new BCryptOptions(workFactor)` throws `ArgumentOutOfRangeException` outside
  that range. A salt or hash with a cost outside it throws `SaltParseException` (v4 accepted costs from 1).
- Salts containing invalid characters throw `SaltParseException` on every target framework. On .NET Framework and .NET
  Standard, v4 hashed those characters as zero bytes.
- `InterrogateHash` and `PasswordNeedsRehash` reject hashes whose length doesn't match their revision.
- Legacy `$2$` hashes are now produced and verified correctly (59 characters, no revision letter).

## New in v5

You don't need any of these to upgrade, but they're worth knowing about:

- **`BCryptOptions`**: an immutable struct for per-call settings that you can build once and reuse. Use `WithWorkFactor`,
  `WithLongPasswordHandling` and `WithPreHash` to derive variants.
- **Enhanced Entropy V3** (`BCryptExtendedV3`): pre-hashes with HMAC-SHA3 and a secret key (a pepper) supplied as an
  `HmacKey`. See [Enhanced Entropy](xref:enhancedEntropy).
- **`BCrypt.ValidateAndUpgradeHash` across schemes**: moves hashes between plain, V2 and V3, and rotates V3 keys.
- **Span overloads**: `HashPassword` and `Verify` accept `ReadOnlySpan<char>`, and the library zeroes its internal buffers
  once it's finished with them.
- **`BCryptSafeString`**: hashes and verifies `SecureString` passwords. See [Common topics](xref:common-topics).
- **[`BCrypt.Net.IdentityExtensions`](xref:identityExtensionsAdoption)**: a bcrypt `IPasswordHasher<TUser>` for ASP.NET
  Core Identity.

For the full list of changes, see [Releases](xref:releases).

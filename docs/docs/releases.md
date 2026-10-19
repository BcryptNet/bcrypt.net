---
uid: releases
---

# Releases

## v5.x

### _v5.0.0_ - Breaking change

- Drops support for .net 2, 3.5, 5.0
- Renamed namespace to `BcryptNet` to fix the issue with the class and namespace clashing.
- `LongPasswordHandling` and `HashType` overloads are replaced by a single `BCryptOptions` parameter (see below).
- `BCryptExtendedV2` no longer creates un-wipeable heap copies of the password; V2/V3 pre-hash buffers are zeroed after use.
- `BCryptExtendedV3` throws `ArgumentNullException` for a null HMAC key instead of silently using an empty key.
- Passwords over 72 bytes throw `PasswordTooLongException`, which derives from `ArgumentException` so existing handlers still catch it.
- Legacy `$2$` hashes are now produced and verified correctly (59 characters, no revision letter); an empty `$2$` password hashes as a single NUL byte, as the original OpenBSD implementation did, instead of throwing.
- Salts with invalid characters or a cost outside 4–31 throw `SaltParseException` on every target framework; .NET Framework and .NET Standard previously hashed invalid characters as zero bytes.
- `HashParser` / `InterrogateHash` reject hashes whose length doesn't match their revision or whose cost is outside 4–31.
- `BCryptPasswordHasher.VerifyHashedPassword` returns `Failed` for empty or unrecognised hashes instead of throwing.

### Migrating to V5

Enhanced Entropy V1 is removed in V5, if you are using this feature you will need to migrate to V2 or V3.

#### Namespace Change

The namespace has been changed to `BCryptNet` to avoid clashes with the class name.

#### Enhanced Entropy V2

The code has been split to avoid the endless growth of the main class and the signatures altered to more clearly show which version is being used.

Before

```csharp
var enhancedHashPassword = BCrypt.EnhancedHashPassword(myPassword);
var validatePassword = BCrypt.EnhancedVerify(myPassword, enhancedHashPassword);
```

After

```csharp
var enhancedHashPassword = BCryptExtendedV2.HashPassword(myPassword);
var validatePassword = BCryptExtendedV2.Verify(myPassword, enhancedHashPassword);
```

#### BCryptOptions

Per-call settings (work factor, long-password handling and pre-hash algorithm) are now passed as a
`BCryptOptions` value instead of through separate overloads. It is an immutable struct, so passing it
does not allocate, and `default(BCryptOptions)` means the library defaults. `HashPassword(password)` and
`HashPassword(password, workFactor)` are unchanged. Hashes are byte-for-byte identical to v4.

| Before | After |
| --- | --- |
| `BCrypt.HashPassword(pw, LongPasswordHandling.Truncate, 12)` | `BCrypt.HashPassword(pw, new BCryptOptions(12, LongPasswordHandling.Truncate))` |
| `BCrypt.HashPassword(pw, salt, LongPasswordHandling.Truncate)` | `BCrypt.HashPassword(pw, salt, new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate))` |
| `BCrypt.Verify(pw, hash, LongPasswordHandling.Truncate)` | `BCrypt.Verify(pw, hash, new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate))` |
| `BCrypt.ValidateAndUpgradeHash(cur, hash, newPw, workFactor: 12)` | `BCrypt.ValidateAndUpgradeHash(cur, hash, newPw, new BCryptOptions(12))` |
| `BCryptExtendedV2.HashPassword(pw, 12, HashType.SHA512)` | `BCryptExtendedV2.HashPassword(pw, new BCryptOptions(12, preHash: HashType.SHA512))` |
| `BCryptExtendedV2.Verify(pw, hash, HashType.SHA512)` | `BCryptExtendedV2.Verify(pw, hash, new BCryptOptions(preHash: HashType.SHA512))` |
| `BCryptExtendedV3.HashPassword(key, pw, salt, HashType.SHA256)` | `BCryptExtendedV3.HashPassword(key, pw, salt, new BCryptOptions(preHash: HashType.SHA256))` |
| `BCryptExtendedV2.ValidateAndUpgradeHash(cur, hash, newPw, HashType.SHA512)` | `BCryptExtendedV2.ValidateAndUpgradeHash(cur, hash, HashType.SHA384, newPw, new BCryptOptions(preHash: HashType.SHA512))` |
| `BCryptExtendedV3.ValidateAndUpgradeHash(key, cur, hash, newPw)` | `BCryptExtendedV3.ValidateAndUpgradeHash(key, cur, hash, HashType.SHA384, newPw)` |


Options can be built once and reused, or adjusted with `WithWorkFactor`, `WithLongPasswordHandling` and `WithPreHash`.
An out-of-range work factor (including 0) now throws `ArgumentOutOfRangeException` when the options are constructed
(previously `ValidateAndUpgradeHash` threw `SaltParseException`); omit it or pass `null` for the default. `PreHash` is rejected by the plain `BCrypt` class.

`BCryptExtendedV2` and `BCryptExtendedV3` now reject `PreHash = HashType.None` with an `ArgumentException`; previously it
silently produced a plain bcrypt hash (and for V3, ignored the HMAC key). Use `BCrypt` for plain bcrypt hashes.
To migrate an existing plain bcrypt hash to an extended one, pass `HashType.None` as the `currentKeyHashType` of
`ValidateAndUpgradeHash`; the options' `LongPasswordHandling` is used to verify that hash, so pass
`LongPasswordHandling.Truncate` if it was created with truncation.

----

## v4.x

- _v4.0.3_ - Addition of .net 6 targeting; tidy up targets.
- _v4.0.2_ - Addition of .net 5 targeting; wrap `shaxxx` creation in using to release.
- _v4.0.0 (breaking changes)_ - A bug in `Enhanced Hashing` was discovered that causes the hashes created to be inoperable between different languages.
  V4 provides the fix for this as well as adding test vectors from PHP and Python to ensure the issue remains fixed in the future. V4 also removes the legacy 384 option that came before Base64 was added.

----

## v3.x

- _v3.5.0_ - A bug in `Enhanced Hashing` was discovered that causes the hashes created to be inoperable between different languages.
  As part of the fix 3.5 release contains the ability to `Verify` and `HashPassword` were given an additional `v4CompatibleEnhancedEntropy` parameter.
  This allows the user to verify their Enhanced hash as normal; then re-hash + store using V4. This functionality is purely to allow migration and is removed in V4.
- _v3.3.3_ -Performance (heap reduction) for netcore and removal of regex <https://github.com/BcryptNet/bcrypt.net/releases/tag/3.3.0>

----

## v2.x 

### _v2.1.3 -_

- Update test SDK
- Match versions between Strong-Signed / Normal package
- Update copyright year in metadata
- Typo correction

### _v2.1.2 -_

- NetStandard2 and Net 4.7 addition
- Correct typo in `PasswordNeedsReshash` to `PasswordNeedsRehash`
- Consolidate config changes

### _v2.1.1 -_

- Minor csproj changes / typo

### _v2.1.0 -_

- Adds enhanced mode; enhanced hashing allows you to opt-in to ensuring optimal entropy on your users passwords by first making use of the fast SHA384 algorithm before BCrypt hashes the password.
- Added Hash interrogation to allow a hash to be passed in and its component parts are returned.
- Added timeouts to regex and set compiler flags for msbuild so < .net 4.5 (where timeouts were added to regex) we use old regex method.
- Alter safe equals from ceq/and to xor/and/ceq moving the check outside of the loop to mitigate against branch prediction causing a timing leak
- Add new method `PasswordNeedsRehash(string hash, int newMinimumWorkLoad)` as a helper method for developers to use when logging a user in to increase legacy workloads
- Add `ValidateAndReplacePassword` method to allow inline password validation and replacement. Throws `BcryptAuthenticationException` in the event of authentication failure.
- Cleaned up XML-doc for intellisense
- Increased compatibility by allowing BCrypt revisions from other frameworks/languages to be validated and generated whilst maintaining compatibility.
- VS2017 RTW changes

### _v2.0.1 -_

- Corrects usage of Secure random number generator
- Change UTF8 handling to safer default (throwOnInvalidBytes: true)
- .NET Encoding.UTF8 encoding instance does not raise exceptions used to encode bytes which cannot represent a valid encoding & will return the same 'unknown' character instead. This can cause entropy loss when converting from bytes to strings.
- Change secure equals to match .net identity implementation
- Inline vars in encipher method

### _v2.0.0 -_

Fresh release packaged for the majority of .net & containing safe-equals to reduce the risks from timing attacks <https://en.wikipedia.org/wiki/Timing_attack> / <https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time>
Technically the implementation details of BCrypt theoretically mitigate against timing attacks. But the Bcrypt.net official validation function was vulnerable to timing attacks as it returned as soon as a non-matching byte was found in the hash comparison.

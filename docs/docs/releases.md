---
uid: releases
---

# Releases

Supported releases:

v4 and v5 will be supported for the foreseable future; with 4 recieving targeting releases and any necessary patches but no new features.

## v5.x

### _v5.0.0_ - Breaking change

See [Upgrading from v4 to v5](xref:upgradingToV5) for a step-by-step guide.

Breaking changes:

- Drops support for .net 2, 3.5, 5.0. Targets `netstandard2.0`, `netstandard2.1`, `net462`, `net472`, `net48`, `net8.0` and `net10.0`.
- The assembly is strong-name signed, so the separate `BCrypt.Net-Next.StrongName` package is retired.
- Renamed namespace from `BCrypt.Net` to `BCryptNet` to fix the issue with the class and namespace clashing.
- Passwords over 72 bytes now throw `PasswordTooLongException` by default (it derives from `ArgumentException`, so existing handlers still catch it); v4 silently truncated them. Pass `LongPasswordHandling.Truncate` to keep the v4 behaviour.
- Optional settings (work factor, long-password handling, pre-hash algorithm) are passed as a single `BCryptOptions` parameter instead of the v4 `bool enhancedEntropy` / `HashType` overloads.
- `EnhancedHashPassword` / `EnhancedVerify` and the `enhancedEntropy` overloads move to `BCryptExtendedV2`; hashes are unchanged.
- `ValidateAndReplacePassword` is renamed `ValidateAndUpgradeHash`.
- `GenerateSalt` and the obsolete `HashString` are removed from the public API.
- Enhanced Entropy V1 is removed.
- Salts with invalid characters or a cost outside 4–31 throw `SaltParseException` on every target framework; .NET Framework and .NET Standard previously hashed invalid characters as zero bytes.
- `HashParser` / `InterrogateHash` reject hashes whose length doesn't match their revision or whose cost is outside 4–31.

Fixes:

- Legacy `$2$` hashes are now produced and verified correctly (59 characters, no revision letter); an empty `$2$` password hashes as a single NUL byte, as the original OpenBSD implementation did, instead of throwing.
- Enhanced hashing no longer leaves un-wipeable heap copies of the password; pre-hash buffers are zeroed after use.

New features:

- Enhanced Entropy V3 (`BCryptExtendedV3`): pre-hashes with HMAC-SHA3 and a secret key. The key is passed as an `HmacKey` rather than a `string`, so it can't be swapped with the password; null throws `ArgumentNullException` and empty keys are rejected.
- `BCrypt.ValidateAndUpgradeHash` overload that moves hashes between schemes (plain, V2, V3) and rotates HMAC keys.
- `ReadOnlySpan<char>` overloads of `HashPassword` and `Verify`, and `BCryptSafeString` for `SecureString` input.
- New package `BCrypt.Net.IdentityExtensions`: a bcrypt `IPasswordHasher<TUser>` for ASP.NET Core Identity. It verifies existing Identity hashes and re-hashes them on login, supports enhanced (V2/V3) hashes through `BCryptHasherOptions.PreHash`, and migrates hashes between schemes through `PreviousPreHashes`. Options are validated at startup and changes apply without a restart. See [ASP.NET Core Identity in v5](xref:identityExtensionsAdoption).

### Migrating to V5

The migration notes are available here [Upgrading from v4 to v5](xref:upgradingToV5). ASP.NET Core Identity users should also read [ASP.NET Core Identity in v5](xref:identityExtensionsAdoption).

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

---
uid: releases
---

# Releases

## v5.x

### _v5.0.0_ - Breaking change

- Drops support for .net 2, 3.5, 5.0
- Renamed namespace to `BcryptNet` to fix the issue with the class and namespace clashing.

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

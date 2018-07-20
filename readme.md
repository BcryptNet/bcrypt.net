# bcrypt.net - next

Porting of bcrypt.codeplex.com with enhanced security, missing fixes, features and better .net support.

[![Build status](https://ci.appveyor.com/api/projects/status/me6tlh95u59jl17d/branch/master?svg=true)](https://ci.appveyor.com/project/ChrisMcKee/bcrypt-net/branch/master)

[![SonarCloud](https://sonarcloud.io/api/project_badges/quality_gate?project=bcryptnet)]()

# Nuget  

Download using nuget or Paket (https://fsprojects.github.io/Paket/)

Package: https://www.nuget.org/packages/BCrypt.Net-Next/
[![NuGet](https://img.shields.io/nuget/v/BCrypt.Net-Next.svg?style=flat-square)](https://www.nuget.org/packages/BCrypt.Net-Next)

Signed Package - https://www.nuget.org/packages/BCrypt.Net-Next.StrongName/
[![NuGet Signed Package](https://img.shields.io/nuget/v/BCrypt.Net-Next.StrongName.svg?style=plastic)](https://www.nuget.org/packages/BCrypt.Net-Next.StrongName)


# How to use

The simplest usage is as follows...

To Hash a password:

`string passwordHash =  BCrypt.HashPassword("my password");`

*Note: Although this library allows you to supply your own salt, it is **highly** advisable that you allow the library to generate the salt for you.
These methods are supplied to maintain compatibility and for more advanced cross-platform requirements that may necessitate their use.*

To Verify a password against a hash (assuming you've stored the hash and retrieved from storage for verification):

`BCrypt.Verify("my password", passwordHash);`

This implementation on hashing will generate a salt automatically for you with the work factor (2^number of rounds) set to 10 (which matches the default across most implementation and is currently viewed as a good level of security/risk).

To save you the maths a small table covering the iterations is provided below. The minimum allowed in this library is 4 for compatibility, the maximum is 31 (at 31 your processor will be wishing for death).

```
| Cost  | Iterations               |
|-------|--------------------------|
|   8   |    256 iterations        |
|   9   |    512 iterations        |
|  10   |  1,024 iterations        |
|  11   |  2,048 iterations        |
|  12   |  4,096 iterations        |
|  13   |  8,192 iterations        |
|  14   | 16,384 iterations        |
|  15   | 32,768 iterations        |
|  16   | 65,536 iterations        |
|  17   | 131,072 iterations       |
|  18   | 262,144 iterations       |
|  19   | 524,288 iterations       |
|  20   | 1,048,576 iterations     |
|  21   | 2,097,152 iterations     |
|  22   | 4,194,304 iterations     |
|  23   | 8,388,608 iterations     |
|  24   | 16,777,216 iterations    |
|  25   | 33,554,432 iterations    |
|  26   | 67,108,864 iterations    |
|  27   | 134,217,728 iterations   |
|  28   | 268,435,456 iterations   |
|  29   | 536,870,912 iterations   |
|  30   | 1,073,741,824 iterations |
|  31   | 2,147,483,648 iterations |

etc
```

and a simple benchmark you can run by creating a console program, adding this BCrypt Library and using this code.

```
    var cost = 16;
    var timeTarget = 100; // Milliseconds
    long timeTaken;
    do
    {
        var sw = Stopwatch.StartNew();

        BCrypt.HashPassword("RwiKnN>9xg3*C)1AZl.)y8f_:GCz,vt3T]PI", workFactor: cost);

        sw.Stop();
        timeTaken = sw.ElapsedMilliseconds;

        cost -= 1;

    } while ((timeTaken) >= timeTarget);

    Console.WriteLine("Appropriate Cost Found: " + (cost + 1));
    Console.ReadLine();
```

This will start at 16 which is `65,536 iterations` and reduce the cost until the time target is reached.
It's up to you what you consider an allowable time, but if it's below 10, I'd seriously advice leaving it at 10
and maybe investing in a larger server package. 


## Enhanced Entropy 

The recommended 56 byte password limit (including null termination byte) for bcrypt relates to the 448 bit limit of the Blowfish key; Any 
bytes beyond that limit are not fully mixed into the hash, as such making the 72 byte absolute limit on bcrypt passwords less relevant 
considering what actual effect on the resulting hash by those bytes.

```
string passwordHash = BCrypt.HashPassword("my password", enhancedEntropy: true);

BCrypt.EnhancedVerify("my password", passwordHash)
```

## Compiling

You'll need at least VS2017 with the current SDK https://www.microsoft.com/net/download;

The nuget packages can be built by running `buildfornuget.cmd`
or 

```
dotnet restore .\src
dotnet pack .\src\BCrypt.Net --configuration Release
```

## Tests

You can run the tests from the main folder by typing `dotnet test .\src\BCrypt.Net.UnitTests\`
Running `TestGenerateSaltWithMaxWorkFactor` will take significant time.

## Description

A .Net port of jBCrypt implemented in C#. It uses a variant of the Blowfish encryption algorithm’s keying schedule, and introduces a work factor, which allows you to determine how expensive the hash function will be, allowing the algorithm to be "future-proof".

## Details
This is, for all intents and purposes, a direct port of jBCrypt written by Damien Miller.  The main differences are the addition of some convenience methods and some mild re-factoring.  The easiest way to verify BCrypt.Net's parity with jBCrypt is to compare the unit tests.

For an overview of why BCrypt is important, see How to Safely Store a Password.  In general, it's a hashing algorithm that can be adjusted over time to require more CPU power to generate the hashes.  This, in essence, provides some protection against Moore's Law.  That is, as computers get faster, this algorithm can be adjusted to require more CPU power.  The more CPU power that's required to hash a given password, the more time a "hacker" must invest, per password.  Since the "work factor" is embedded in the resultant hash, the hashes generated by this algorithm are forward/backward-compatible.

## Why BCrypt

### From How to Safely Store a Password:

It uses a variant of the Blowfish encryption algorithm’s keying schedule and introduces a work factor, which allows you to determine how expensive the hash function will be. Because of this, BCrypt can keep up with Moore’s law. As computers get faster you can increase the work factor and the hash will get slower.

### Blowfish-based scheme - Versioning/BCrypt Revisions

> Niels Provos and David Mazières designed a crypt() scheme called bcrypt based on Blowfish, and presented it at USENIX in 1999.[14]

The printable form of these hashes starts with $2$, $2a$, $2b$, $2x$ or $2y$ depending on which variant of the algorithm is used:

```
$2$ – Currently obsolete
$2a$ – The current key used to identify this scheme. 
       Since a major security flaw was discovered in 2011 in a third-party implementation of the algorithm, 
       hashes indicated by this string are now ambiguous and might have been generated by the flawed 
       implementation, or a subsequent fixed, implementation. 
       The flaw may be triggered by some password strings containing non-ASCII characters, such as specially 
       crafted password strings.
$2b$ – Used by some recent implementations which include a mitigation to a wraparound problem. 
       Previous versions of the algorithm have a problem with long passwords. By design, long passwords 
       are truncated at 72 characters, but there is an 8-bit wraparound problem with certain password 
       lengths resulting in weak hashes.
$2x$ – Post-2011 bug discovery, old hashes can be renamed to be $2x$ to indicate that they were generated with 
       the broken algorithm. These hashes are still weak, but at least it's clear which algorithm was used to 
       generate them.
$2y$ – Post Post-2011 bug discovery, $2y$ may be used to unambiguously use the new, corrected algorithm. On an 
       implementation suffering from the bug, $2y$ simply won't work. On a newer, fixed implementation, it will 
       produce the same result as using $2a$.
```

First and foremost this library originated as a port of jBCrypt from `mindrot`, ans subsequently the bcrypt revision
was set to match, which in this case is `$2a$`.
This has been changed as handling only the single revision causes issues cross-platform with implementations that moved
altered their revision to handle migrations and other issues.

```
The original bcrypt code (released in OpenBSD 2.1) identified itself as
$2$. Shortly after release, a bug was fixed and the hash identifier
changed to $2a$. Support for "minor" versions wasn't really
planned, but it was backwards compatible.

Solar Designer wrote a second implementation of bcrypt. This
reimplementation suffered from a flaw dealing with 8 bit characters
and led to the introduction of the 'x' and 'y' flavours. OpenBSD did
not have this problem and supports neither 'x' nor 'y' hash versions.

---

Solar found a bug in their OpenBSD implementation of bcrypt when hashing
long passwords. The length is stored in an unsigned char type, which
will overflow and wrap at 256. Although we consider the existence of
affected hashes very rare, in order to differentiate hashes generated
before and after the fix, we are introducing a new minor 'b'.

OpenBSD 5.5 (coming this spring) will accept and verify 'b' hashes,
although it will still generate 'a' hashes. OpenBSD 5.6 (coming this
fall) will change to generating 'b' hashes by default.

A future release of Solar's bcrypt code should also support 'b'.
```

**There is no difference between 2a, 2x, 2y, and 2b. They all output the same result.**

* https://github.com/spring-projects/spring-security/issues/3320
* https://en.wikipedia.org/wiki/Crypt_(C)#Blowfish-based_scheme
* http://undeadly.org/cgi?action=article&sid=20140224132743
* http://marc.info/?l=openbsd-misc&m=139320023202696

# Releases

v2.1.3+ release notes are here https://github.com/BcryptNet/bcrypt.net/releases

*v2.1.3 -*
* Update test SDK
* Match versions between Strongsigned / Normal package
* Update copyright year in metadata
* Typo correction

*v2.1.2 -*
* NetStandard2 and Net 4.7 addition
* Correct typo in `PasswordNeedsReshash` to `PasswordNeedsRehash`
* Consolidate config changes

*v2.1.1 -*
* Minor csproj changes / typo

*v2.1.0 -*

* Adds enhanced mode; enhanced hashing allows you to opt-in to ensuring optimal entropy on your users passwords by first making use of the fast SHA384 algorithm before BCrypt hashes the password.
* Added Hash interrogation to allow a hash to be passed in and its component parts are returned.
 * Added timeouts to regex and set compiler flags for msbuild so < .net 4.5 (where timeouts were added to regex) we use old regex method.
* Alter safe equals from ceq/and to xor/and/ceq moving the check outside of the loop to mitigate against branch prediction causing a timing leak
* Add new method `PasswordNeedsReshash(string hash, int newMinimumWorkLoad)` as a helper method for developers to use when logging a user in to increase legacy workloads
* Add `ValidateAndReplacePassword` method to allow inline password validation and replacement. Throws `BcryptAuthenticationException` in the event of authentication failure.
* Cleaned up XML-doc for intellisense
* Increased compatibility by allowing BCrypt revisions from other frameworks/languages to be validated and generated whilst maintaining compatibility.
* VS2017 RTW changes

*v2.0.1 -*

* Corrects usage of Secure random number generator
* Change UTF8 handling to safer default (throwOnInvalidBytes: true)
 * .NET Encoding.UTF8 encoding instance does not raise exceptions used to encode bytes which cannot represent a valid encoding & will return the same 'unknown' character instead. This can cause entropy loss when converting from bytes to strings.
* Change secure equals to match .net identity implementation
* Inline vars in encipher method

*v2.0.0 -*

Fresh release packaged for the majority of .net & containing safe-equals to reduce the risks from timing attacks https://en.wikipedia.org/wiki/Timing_attack / https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time
Technically the implementation details of BCrypt theoretically mitigate against timing attacks. But the Bcrypt.net official validation function was vulnerable to timing attacks as it returned as soon as a non-matching byte was found in the hash comparison.


# bcrypt.net - next

> [!NOTE]
> The main code, documentation and website refer to V5 which is being prepared for release

[![Documentation](https://img.shields.io/badge/Documentation-Online-blue.svg?style=flat-square)](https://bcryptnet.chrismckee.uk/)

[![NuGet](https://img.shields.io/nuget/v/BCrypt.Net-Next.svg?style=flat-square)](https://www.nuget.org/packages/BCrypt.Net-Next)

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/BcryptNet/bcrypt.net/.github%2Fworkflows%2Fcodeql-analysis.yml)

[![License](https://img.shields.io/github/license/BcryptNet/bcrypt.net.svg?style=flat-square)]

## Description

A `.Net` port of jBCrypt implemented in C#. It uses a variant of the Blowfish encryption algorithm’s keying schedule, and introduces a work factor, which allows you to determine how expensive the hash function will be, allowing the algorithm to be "future-proof".

## Details

This is, for all intents and purposes, a direct port of jBCrypt written by Damien Miller. The main differences are the addition of some convenience methods and some mild re-factoring. The easiest way to verify BCrypt.Net's parity with jBCrypt is to compare the unit tests.

For an overview of why BCrypt is important, see How to Safely Store a Password. In general, it's a hashing algorithm that can be adjusted over time to require more CPU power to generate the hashes. This, in essence, provides some protection against Moore's Law. That is, as computers get faster, this algorithm can be adjusted to require more CPU power. The more CPU power that's required to hash a given password, the more time a "hacker" must invest, per password. Since the "work factor" is embedded in the resultant hash, the hashes generated by this algorithm are forward/backward-compatible.

## Why BCrypt

### From How to Safely Store a Password

It uses a variant of the Blowfish encryption algorithms keying schedule and introduces a work factor, which allows you to determine how expensive the hash function will be. Because of this, BCrypt can keep up with Moore’s law. As computers get faster you can increase the work factor and the hash will get slower.

## Nuget

Package: <https://www.nuget.org/packages/BCrypt.Net-Next/>
[![NuGet](https://img.shields.io/nuget/v/BCrypt.Net-Next.svg?style=flat-square)](https://www.nuget.org/packages/BCrypt.Net-Next)

## Quick Start

**To Hash a password:**

File-scoped namespaces are shown; imagine curly brackets if you need to.

`Top level namespace`

```csharp
namespace MyDotNetProject;

using BCryptNet;

// Hash a password
string passwordHash =  BCrypt.HashPassword("my password");

// Verify a password
if(BCrypt.Verify("my password", passwordHash))
{
    // Password is correct
}

```

_Note: Although this library allows you to supply your own salt, it is **highly** advisable that you allow the library to generate the salt for you.
These methods are supplied to maintain compatibility and for more advanced cross-platform requirements that may necessitate their use._

This implementation on hashing will generate a salt automatically for you with the work factor (2^number of rounds) set to 11 (which matches the default across most implementation and is currently viewed as a good level of security/risk).

There are various examples in our [test-harness folder](https://github.com/BcryptNet/bcrypt.net/tree/main/testharnesses) and [unit-tests](https://github.com/BcryptNet/bcrypt.net/blob/main/tests/UnitTests/BCryptTests.cs)

---
uid: identityExtensionsAdoption
---

# ASP.NET Core Identity in v5

`BCrypt.Net.IdentityExtensions` is a new package in v5; there was no v4 equivalent. It replaces ASP.NET Core Identity's
`IPasswordHasher<TUser>` with bcrypt, so you no longer need to write your own hasher.

This page covers adopting it, either from Identity's built-in hasher or from your own hasher built on BCrypt.Net v4. For
the full list of options, see [ASP.NET Core Identity](xref:identity).

## Install

```shell
dotnet add package BCrypt.Net.IdentityExtensions
```

The package targets `net8.0` and `net10.0`, and depends on `BCrypt.Net-Next` v5.

## Register

`UseBcrypt` is in the `Microsoft.Extensions.DependencyInjection` namespace, so it's available without an extra `using`.
The option types are in `BCryptNet.IdentityExtensions`, and the enums they use (`LongPasswordHandling`, `PreHashScheme`,
`HashType`) are in `BCryptNet`.

```csharp
using BCryptNet;
using BCryptNet.IdentityExtensions;

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>();

builder.Services.UseBcrypt<IdentityUser>(o =>
{
    o.WorkFactor = 12;
    o.RehashPasswords = true;
});
```

The defaults are:

| Option | Default |
| --- | --- |
| `WorkFactor` | `11` |
| `RehashPasswords` | `false`: hashes below `WorkFactor` aren't re-hashed on login |
| `LongPasswordHandling` | `Throw`: hashing or verifying a password over 72 bytes against plain bcrypt throws `PasswordTooLongException` |
| `PreHash` | plain bcrypt (no pre-hash) |
| `PreviousPreHashes` | empty |

Options are validated at startup, and changes apply without a restart. See [ASP.NET Core Identity](xref:identity).

## Coming from Identity's built-in hasher

You don't need to do anything else. Existing Identity (v2 and v3 format) hashes still verify. They return
`SuccessRehashNeeded`, so Identity re-hashes each password with bcrypt on the user's next successful login.

## Coming from your own hasher built on BCrypt.Net v4

If you wrote an `IPasswordHasher<TUser>` that called v4's `BCrypt.HashPassword` / `BCrypt.Verify`, delete it and register
`UseBcrypt` instead. First, check how your existing hashes were created.

### Plain v4 hashes

Plain bcrypt hashes (`$2a$...`, `$2b$...`) are stored as they are and verify with the default options. You don't need to
make any changes.

If any of your users have passwords over 72 bytes, v4 silently truncated them, and the default `Throw` setting makes
verifying those passwords throw. Set `LongPasswordHandling` to `Truncate` to keep accepting them. Better still, move
everyone to a pre-hashed scheme so the whole password counts from then on:

```csharp
builder.Services.UseBcrypt<IdentityUser>(o =>
{
    o.LongPasswordHandling = LongPasswordHandling.Truncate;     // verify existing v4 hashes as v4 did
    o.PreHash = new PreHashOptions { Scheme = PreHashScheme.Sha2 }; // new hashes: SHA384 + bcrypt
    o.PreviousPreHashes.Add(new PreHashOptions());              // existing plain hashes: re-hashed on login
});
```

### Enhanced v4 hashes

Hashes from v4's `EnhancedHashPassword` (or `enhancedEntropy: true`) look exactly like plain bcrypt hashes. The hasher
can't tell them apart, so it treats untagged hashes as plain bcrypt, and they **won't verify**.

The hasher marks pre-hashed passwords with a scheme tag in front of the bcrypt hash, for example
`$bcnet-sha2-384$2a$11$...`. Before switching, add the tag that matches the `HashType` the hashes were created with:

| v4 `HashType` | Tag to prepend |
| --- | --- |
| `SHA384` (the v4 default) | `$bcnet-sha2-384` |
| `SHA256` | `$bcnet-sha2-256` |
| `SHA512` | `$bcnet-sha2-512` |

For example, with the default Identity schema on SQL Server:

```sql
UPDATE AspNetUsers
SET PasswordHash = '$bcnet-sha2-384' + PasswordHash
WHERE PasswordHash LIKE '$2%';
```

Only run this if *all* your bcrypt hashes are enhanced. If plain and enhanced hashes are mixed, tag only the enhanced
ones; you'll need your own record of which is which.

Then configure the scheme. You can keep it for new hashes:

```csharp
builder.Services.UseBcrypt<IdentityUser>(o =>
{
    o.PreHash = new PreHashOptions { Scheme = PreHashScheme.Sha2, Digest = HashType.SHA384 };
});
```

Or list it as a previous scheme so users move to the current one on their next login (here, HMAC-SHA3 with a secret key):

```csharp
builder.Services.UseBcrypt<IdentityUser>(o =>
{
    o.PreHash = new PreHashOptions
    {
        Scheme = PreHashScheme.HmacSha3,
        HmacKey = builder.Configuration["BCrypt:PreHash:HmacKey"], // keep this out of appsettings.json
    };
    o.PreviousPreHashes.Add(new PreHashOptions { Scheme = PreHashScheme.Sha2, Digest = HashType.SHA384 });
});
```

Tagging stops a SHA2 hash from being checked as plain bcrypt. Without the tag, anyone who had an unsalted SHA2 digest of
a password could log in with it. See
[Migrating existing hashes](xref:identity#migrating-existing-hashes).

## Next steps

- [ASP.NET Core Identity](xref:identity): configuration binding, live reload and HMAC key rotation.
- [Enhanced Entropy](xref:enhancedEntropy): how the V2 and V3 pre-hash schemes work.
- [Upgrading from v4 to v5](xref:upgradingToV5): changes to the core `BCrypt.Net-Next` API.

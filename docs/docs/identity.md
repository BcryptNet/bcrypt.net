---
uid: identity
---

# ASP.NET Core Identity

`BCrypt.Net.IdentityExtensions` replaces Identity's `IPasswordHasher<TUser>` with bcrypt.

```csharp
builder.Services.UseBcrypt<IdentityUser>();
```

Existing ASP.NET Identity (v2/v3) hashes keep working. They verify with `SuccessRehashNeeded`, so Identity re-hashes them with
bcrypt on the user's next successful login.

## Options

```csharp
builder.Services.UseBcrypt<IdentityUser>(o =>
{
    o.WorkFactor = 12;
    o.RehashPasswords = true; // re-hash hashes below WorkFactor on login
    o.LongPasswordHandling = LongPasswordHandling.Throw;
});
```

Or bind them from configuration:

```csharp
builder.Services.Configure<BCryptHasherOptions>(builder.Configuration.GetSection("BCrypt"));
builder.Services.UseBcrypt<IdentityUser>();
```

The options are validated at startup, so an invalid work factor, an unsupported scheme or a missing HMAC key stops the app
from starting instead of failing the first login.

## Enhanced (pre-hashed) bcrypt

Set `PreHash` to hash new passwords with [Enhanced Entropy](xref:enhancedEntropy) V2 (`Sha2`) or V3 (`HmacSha3`):

```json
{
  "BCrypt": {
    "WorkFactor": 12,
    "PreHash": { "Scheme": "HmacSha3", "Digest": "SHA384" }
  }
}
```

The V3 HMAC key (`BCrypt:PreHash:HmacKey`) is a secret. Supply it from user secrets, environment variables or a key vault,
not from `appsettings.json`. It is never included in the options' `ToString()`.

HMAC-SHA3 needs OS support (Windows 11 build 25324+, or OpenSSL 1.1.1+ on Linux; not macOS).

## Migrating existing hashes

Bcrypt hashes don't record which pre-hash produced them, so after changing `PreHash` the hasher has to be told which schemes
existing hashes may use. List them in `PreviousPreHashes`. They are tried in order when a password doesn't verify under the
current scheme, and a match returns `SuccessRehashNeeded`, so the user is moved to the current scheme on their next login.

```json
{
  "BCrypt": {
    "PreHash": { "Scheme": "HmacSha3" },
    "PreviousPreHashes": [
      { "Scheme": "None" },
      { "Scheme": "Sha2", "Digest": "SHA384" }
    ]
  }
}
```

The same mechanism rotates the V3 HMAC key: set the new key on `PreHash` and add the old one as a previous `HmacSha3` entry.

Each previous scheme costs one extra bcrypt computation on every failed login. Remove entries once your users have migrated.

## Live reload

Option changes apply without a restart, when the options come from a configuration source that reloads (e.g. `appsettings.json`
with `reloadOnChange`, or Azure App Configuration with refresh). Each change is picked up on the next hash or verify. That
includes switching scheme, adding a `PreviousPreHashes` entry and rotating the HMAC key.

If a reloaded configuration is invalid (a missing HMAC key, an unknown scheme, an out-of-range work factor), the hasher keeps
using the last valid options and logs an error (event `InvalidReload`). It logs again (event `ReloadRecovered`) once a valid
configuration is applied. The reload itself also reports the error, as it does for any validated options.

To rotate a key without a window where logins fail, apply the change in one update: set the new key on `PreHash` and move
the old key to `PreviousPreHashes` together.

`UseBcrypt` registers the hasher with live options. If you register `BCryptPasswordHasher<TUser>` yourself, use a factory
that calls the `IOptionsMonitor<BCryptHasherOptions>` constructor, as the container can't choose between its constructors.

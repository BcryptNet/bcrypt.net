---
uid: enhancedEntropy
---

# Enhanced Entropy

The recommended 56 byte password limit (including null termination byte) for bcrypt relates to the 448 bit limit of the Blowfish key; Any
bytes beyond that limit are not fully mixed into the hash, as such making the 72 byte absolute limit on bcrypt passwords less relevant
considering what actual effect on the resulting hash by those bytes.

Other languages have handled this perceived issue by pre-hashing the passphrase/password to increase the used entropy, dropbox being one of the more public articles on this.

- <https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/>
- <https://crypto.stackexchange.com/questions/42415/dropbox-password-security>

You can opt into enhanced hashing simply using the following code (basically prefixing the method calls with Enhanced)

```csharp
var enhancedHashPassword = BCrypt.EnhancedHashPassword(myPassword);
var validatePassword = BCrypt.EnhancedVerify(myPassword, enhancedHashPassword);
```

By default, the library uses SHA384 hashing of the passphrase, the material generated is then passed to bcrypt to form your hash via the usual bcrypt routine.
If you want to specify a different version of SHA, or just wish to explicitly set in your code the version used in case it ever changes in a major release of the library,
you can do so by using the following change to the above.

```csharp
var enhancedHashPassword = BCrypt.EnhancedHashPassword(myPassword, hashType: HashType.SHA384);
var validatePassword = BCrypt.EnhancedVerify(myPassword, enhancedHashPassword, hashType:HashType.SHA384);
```

_Why SHA384?_ It’s a good balance of performance, security, collision protection and is the only version that wasn't vulnerable to length extension attacks <https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks> .

_Should I use Enhanced Entropy?_ You lose nothing by using it

_Why would I need to change the SHA type?_ Some libraries like PassLib hash using SHA256, so mostly a compatibility thing. DropBox used SHA512 so if you worked at dropbox you’d want compatibility. The enhancing is mostly a convenience extension in that you could already pre-hash and pass into the standard method calls.

_What does it do?_ We take the utf8 bytes of your password as inputBytes SHA hash them, convert to base64 (for compatibility with other language implementations) then use those bytes to perform the standard bcrypt call.

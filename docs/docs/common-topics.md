---
uid: common-topics
---


## Secure String / In memory secrets / protection against memory dumps or RAM attacks




Refs:

* [.net Remarks on SecureString](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring)
* [Dotnet Design Conversation around replacing SecureString](https://github.com/dotnet/designs/pull/147)
* [Microsoft Docs on SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring)

Relevant .net Code

* <https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Primitives/src/System/Net/NetworkCredential.cs#L104>
* [<https://github.com/dotnet/runtime/blob/d099f075e45d2aa6007a22b71b45a08758559f80/src/libraries/System.Private.CoreLib/src/System/Security/SecureString.cs>](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Security/SecureString.cs)

Related Issues

* https://github.com/BcryptNet/bcrypt.net/issues/83
* https://github.com/dotnet/runtime/issues/118484#issuecomment-3165098658

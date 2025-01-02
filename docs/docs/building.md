---
uid: building
---

# Building the Library from source

The library is built using the .NET Core SDK, and can be built on Windows, Linux, and MacOS.

## Prerequisites

- [.NET Core SDK](https://dotnet.microsoft.com/download)
- [Git](https://git-scm.com/downloads)
- [Visual Studio Code](https://code.visualstudio.com/) or your favorite editor (VSCode / Visual Studio / Rider / etc)

## Getting the source

Clone the repository using git:

```bash
git clone git@github.com:BcryptNet/bcrypt.net.git
```

## Building the library

Navigate to the root of the repository and run the following command:

```bash
dotnet build
```

## Tests

You can run the tests from the main folder by typing `dotnet test`
Running `TestGenerateSaltWithMaxWorkFactor` will take significant time.

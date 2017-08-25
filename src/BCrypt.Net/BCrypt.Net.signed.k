<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <Description>BCrypt.Net, C# implementation of BCrypt, OpenBSD-style Blowfish password hashing</Description>
    <AssemblyTitle>BCrypt.Net-Next</AssemblyTitle>
    <AssemblyName>BCrypt.Net-Next</AssemblyName>

    <VersionPrefix>2.1.0</VersionPrefix>
    <Version>2.1.1</Version>
    <AssemblyVersion>2.1.1.0</AssemblyVersion>
    <FileVersion>2.1.1.0</FileVersion>

    <Authors>https://github.com/BcryptNet/bcrypt.net/graphs/contributors</Authors>
    <TargetFrameworks>net20;net35;net40;net45;net451;net452;net462;netstandard1.3;netstandard1.6;netstandard2.0</TargetFrameworks>
    <OutputTypeEx>Library</OutputTypeEx>

    <PublicSign Condition=" '$(OS)' != 'Windows_NT' ">true</PublicSign>

    <PackageId>BCrypt.Net-Next</PackageId>
    <Title>BCrypt.Net - Next</Title>
    <Authors>Chris McKee, Ryan D. Emerl, Damien Miller</Authors>
    <Copyright>2006-2017 Chris McKee, Ryan D. Emerl, Damien Miller</Copyright>
    <Description>A fixed, enhanced and namespace compatible version of BCrypt.Net port of jBCrypt implemented in C#. It uses a variant of the Blowfish encryption algorithm’s keying schedule, and introduces a work factor, which allows you to determine how expensive the hash function will be, allowing the algorithm to be "future-proof".</Description>
    <Summary>A fixed, enhanced and namespace compatible version of BCrypt.Net port of jBCrypt implemented in C#.</Summary>
    <PackageTags>bcrypt;BCrypt.Net;cryptography;hashing;password;security,hash;crypto;blowfish</PackageTags>
    <PackageReleaseNotes>See https://github.com/BcryptNet/bcrypt.net/releases </PackageReleaseNotes>
    <PackageIconUrl>https://raw.githubusercontent.com/BcryptNet/bcrypt.net/master/ico64.png</PackageIconUrl>
    <PackageProjectUrl>https://github.com/BcryptNet/bcrypt.net</PackageProjectUrl>
    <PackageLicenseUrl>https://github.com/BcryptNet/bcrypt.net/blob/master/licence.txt</PackageLicenseUrl>
    <GeneratePackageOnBuild>True</GeneratePackageOnBuild>
    <PackageRequireLicenseAcceptance>false</PackageRequireLicenseAcceptance>

    <RepositoryType>git</RepositoryType>
    <RepositoryUrl>https://github.com/BcryptNet/bcrypt.net</RepositoryUrl>

    <SignAssembly>True</SignAssembly>
    <AssemblyOriginatorKeyFile>bcrypt.net.snk.pfx</AssemblyOriginatorKeyFile>
    <DelaySign>False</DelaySign>
  </PropertyGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net20' ">
    <Reference Include="System" />
  </ItemGroup>
  <PropertyGroup Condition=" '$(TargetFramework)' == 'net20' ">
    <DefineConstants>$(DefineConstants);LEGACY</DefineConstants>
  </PropertyGroup>

  <PropertyGroup Condition=" '$(TargetFramework)' == 'net35' ">
    <DefineConstants>$(DefineConstants);LEGACY</DefineConstants>
  </PropertyGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net35' ">
    <Reference Include="System" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net40' ">
    <Reference Include="System" />
  </ItemGroup>

  <PropertyGroup Condition=" '$(TargetFramework)' == 'net40' ">
    <DefineConstants>$(DefineConstants);LEGACY</DefineConstants>
  </PropertyGroup>

  <PropertyGroup Condition="'$(Configuration)|$(TargetFramework)|$(Platform)'=='Debug|net20|AnyCPU'">
    <DocumentationFile>bin\Debug\BCrypt.Net-Next.xml</DocumentationFile>
  </PropertyGroup>

  <PropertyGroup Condition="'$(Configuration)'=='Release'">
    <DocumentationFile>bin\Release\$(TargetFramework)\BCrypt.Net-Next.xml</DocumentationFile>
  </PropertyGroup>

  <PropertyGroup Condition="'$(Configuration)|$(TargetFramework)|$(Platform)'=='Release|net20|AnyCPU'">
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
  </PropertyGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net45' ">
    <Reference Include="System" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net451' ">
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
    <Reference Include="System" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net452' ">
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
    <Reference Include="System" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'net462' ">
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
    <Reference Include="System" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'netstandard1.3' ">
    <PackageReference Include="System.Diagnostics.Debug" Version="4.3.0" />
    <PackageReference Include="System.Net.Primitives" Version="4.3.0" />
    <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
    <PackageReference Include="System.Security.Cryptography.Algorithms" Version="4.3.0" />
    <PackageReference Include="System.Text.Encoding.Extensions" Version="4.3.0" />
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
  </ItemGroup>

  <ItemGroup Condition=" '$(TargetFramework)' == 'netstandard1.6' ">
    <PackageReference Include="System.Diagnostics.Debug" Version="4.3.0" />
    <PackageReference Include="System.Net.Primitives" Version="4.3.0" />
    <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
    <PackageReference Include="System.Security.Cryptography.Algorithms" Version="4.3.0" />
    <PackageReference Include="System.Text.Encoding.Extensions" Version="4.3.0" />
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
  </ItemGroup>


  <!--<ItemGroup Condition=" '$(TargetFramework)' == 'netcoreapp1.0' ">
        <PackageReference Include="System.Diagnostics.Debug" Version="4.3.0" />
        <PackageReference Include="System.Net.Primitives" Version="4.3.0" />
        <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
        <PackageReference Include="System.Security.Cryptography.Algorithms" Version="4.3.0" />
        <PackageReference Include="System.Text.Encoding.Extensions" Version="4.3.0" />
        <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
    </ItemGroup>

    <ItemGroup Condition=" '$(TargetFramework)' == 'netcoreapp1.1' ">
        <PackageReference Include="System.Diagnostics.Debug" Version="4.3.0" />
        <PackageReference Include="System.Net.Primitives" Version="4.3.0" />
        <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
        <PackageReference Include="System.Security.Cryptography.Algorithms" Version="4.3.0" />
        <PackageReference Include="System.Text.Encoding.Extensions" Version="4.3.0" />
        <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
    </ItemGroup>-->

  <ItemGroup>
    <Folder Include="Properties\" />
  </ItemGroup>

</Project>

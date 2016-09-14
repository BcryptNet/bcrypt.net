echo Restore Nuget
dotnet restore .\src
echo Pack for Nuget
dotnet pack .\src\BCrypt.Net --configuration Release
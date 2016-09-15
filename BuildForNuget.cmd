@echo off
color 0E
echo " ____   ___  ____  _  _  ____  ____ "
echo "(  _ \ / __)(  _ \( \/ )(  _ \(_  _)"
echo " ) _ <( (__  )   / \  /  )___/  )(  "
echo "(____/ \___)(_)\_) (__) (__)   (__) "
echo ""
set /p vers= "Enter Version Suffix: "
echo Restore Nuget
dotnet restore .\src
echo Pack for Nuget
dotnet pack .\src\BCrypt.Net --configuration Release --version-suffix=%vers%
color 0F
pause
@echo on



@echo off
rem Compares NuGet releases of BCrypt.Net-Next; the version x runtime jobs are defined in BCryptBasics.cs
pushd "%~dp0"
dotnet run --configuration Release --framework net10.0 -- --filter "*" %*
set EXITCODE=%ERRORLEVEL%
popd
exit /b %EXITCODE%

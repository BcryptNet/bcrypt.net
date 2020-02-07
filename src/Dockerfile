FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS test
WORKDIR /src
COPY ./ ./
#RUN dotnet test BCrypt.Net.UnitTests
RUN dotnet build BCrypt.Net.sln -c Benchmark --framework netcoreapp3.1
RUN dotnet run --project Benchmark/Benchmark.csproj  -c Benchmark --framework netcoreapp3.1
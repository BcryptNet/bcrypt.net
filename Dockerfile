FROM mcr.microsoft.com/dotnet/sdk:10.0 AS test
WORKDIR /src
COPY ./ ./
#RUN dotnet test BCrypt.Net.UnitTests
RUN dotnet build BCrypt.Net.sln -c Benchmark --framework net10.0
RUN dotnet run --project Benchmark/Benchmark.csproj -c Benchmark --framework net10.0
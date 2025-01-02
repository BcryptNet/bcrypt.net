FROM mcr.microsoft.com/dotnet/sdk:9.0 AS test
WORKDIR /src
COPY ./ ./
#RUN dotnet test BCrypt.Net.UnitTests
RUN dotnet build BCrypt.Net.sln -c Benchmark --framework net9.0
RUN dotnet run --project Benchmark/Benchmark.csproj -c Benchmark --framework net9.0
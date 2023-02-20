# Benchmarks

Running these 

`dotnet run -c Release -f net48 -- --runtimes net48 net6.0 --platform x64`

or 

`dotnet run -c Release -f net48 -- --runtimes net48 net6.0 --filter * --stopOnFirstError --platform x64`

_Change the framework and remove the netfwk runtimes if running on linux._

Select which test to run; hit enter.

Further docs on valid params available here https://benchmarkdotnet.org/articles/guides/console-args.html


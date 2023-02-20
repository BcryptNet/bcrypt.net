REM --- Recursively remove all /bin and /obj directories --- 

for /d /r . %%d in (bin,obj,.vs,.idea,_ReSharper.Caches) do @if exist "%%d" rd /s/q "%%d"

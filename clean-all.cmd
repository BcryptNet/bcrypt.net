REM --- Recursively remove all /bin and /obj directories --- 

for /d /r . %%d in (bin,obj) do @if exist "%%d" rd /s/q "%%d"

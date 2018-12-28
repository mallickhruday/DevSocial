@ECHO OFF
CLS
ECHO ====== Dev Social Identity Server Migration scripts =======
ECHO ====== Dev Social =======
ECHO.

dotnet ef database update --context PersistedGrantDbContext
dotnet ef database update --context ConfigurationDbContext
dotnet ef database update --context ApplicationDbContext

ECHO ====== Done =======

GOTO End

:End
@pause
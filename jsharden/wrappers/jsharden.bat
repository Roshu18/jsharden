@echo off
REM ============================================================
REM  jsharden drag-and-drop wrapper (Windows)
REM  Usage: drag a .js file (or a folder) onto this .bat file.
REM  Output: <filename>.hardened.js in the same folder.
REM
REM  To change the profile, edit the --profile line below.
REM  Profiles: light | balanced | max
REM ============================================================

setlocal

REM Where is this .bat? jsharden should be installed globally OR sit next to it.
set "HERE=%~dp0"

REM Pick a profile.
set "PROFILE=balanced"

REM If jsharden is installed globally, npx will find it.
REM Otherwise, run the local install in the same dir as the .bat.
where jsharden >nul 2>nul
if errorlevel 1 (
  REM Try the local install.
  if exist "%HERE%node_modules\.bin\jsharden.cmd" (
    set "JSHARDEN=%HERE%node_modules\.bin\jsharden.cmd"
  ) else (
    echo [error] jsharden not found. Install with:  npm install -g jsharden
    pause
    exit /b 1
  )
) else (
  set "JSHARDEN=jsharden"
)

REM No file dragged in — print help.
if "%~1"=="" (
  echo Drag a .js file or folder onto this .bat to harden it.
  echo.
  echo Or run from a terminal:
  echo   jsharden ^<file.js^> --profile %PROFILE%
  pause
  exit /b 0
)

echo [jsharden] hardening %*  (profile=%PROFILE%)
call %JSHARDEN% %* --profile %PROFILE%
if errorlevel 1 (
  echo.
  echo [jsharden] FAILED — see error above.
  pause
  exit /b %errorlevel%
)

echo.
echo [jsharden] done. Output written next to the input.
pause
endlocal

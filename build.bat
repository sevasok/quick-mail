@echo off
echo Building local client...
go build -ldflags="-s -w" -o sokolabs-mail.exe .
if %errorlevel%==0 (echo Built: sokolabs-mail.exe) else (echo Build failed)
pause
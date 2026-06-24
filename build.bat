@echo off
echo Building Quick Mail client...
go build -ldflags="-s -w" -o quick-mail.exe .
if %errorlevel%==0 (echo Built: quick-mail.exe) else (echo Build failed)
pause
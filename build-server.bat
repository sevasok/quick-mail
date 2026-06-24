@echo off
echo Building Quick Mail server for Linux...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o quick-mail-server .\server
if %errorlevel%==0 (echo Built: quick-mail-server) else (echo Build failed)
set GOOS=
set GOARCH=
pause
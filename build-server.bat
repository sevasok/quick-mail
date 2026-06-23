@echo off
echo Building VPS server for Linux...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o sokolabs-server .\server
if %errorlevel%==0 (echo Built: sokolabs-server) else (echo Build failed)
set GOOS=
set GOARCH=
pause
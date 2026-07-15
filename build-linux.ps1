$ErrorActionPreference = 'Stop'
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
New-Item -ItemType Directory -Force -Path "$PSScriptRoot\dist" | Out-Null
go test ./...
go build -trimpath -ldflags="-s -w" -o "$PSScriptRoot\dist\tor-country-manager-linux-amd64" .
Write-Host "Built dist/tor-country-manager-linux-amd64"


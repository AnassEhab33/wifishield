Write-Host "=========================================" -ForegroundColor Red
Write-Host "   Deauth Attack Simulator (Test Script) " -ForegroundColor Red
Write-Host "=========================================" -ForegroundColor Red

# Find the currently connected Wi-Fi profile name
$ssid_match = (netsh wlan show interfaces | Select-String -Pattern "^\s+Profile\s+:\s+(.*)$")

if (-not $ssid_match) {
    Write-Host "Error: You do not appear to be connected to a Wi-Fi network." -ForegroundColor Yellow
    Write-Host "Please connect to a network first to run the simulation."
    exit
}

$ssid = $ssid_match.Matches.Groups[1].Value.Trim()

Write-Host "Target SSID: $ssid" -ForegroundColor Cyan
Write-Host "Simulating rapid Management Frame disconnections..."
Write-Host ""

for ($i=1; $i -le 5; $i++) {
    Write-Host "[Attack $i/5] Forcing disconnect..." -ForegroundColor Yellow
    netsh wlan disconnect | Out-Null
    Start-Sleep -Seconds 1
    
    Write-Host "          Client auto-reconnecting..." -ForegroundColor Gray
    netsh wlan connect name=$ssid | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "Simulation complete!" -ForegroundColor Green
Write-Host "Switch back to the WifiShield scan (it should still be running or run it now)."

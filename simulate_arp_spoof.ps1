Write-Host "=========================================" -ForegroundColor Red
Write-Host "   ARP Spoof Simulator (Test Script)     " -ForegroundColor Red
Write-Host "=========================================" -ForegroundColor Red

Write-Host "Detecting active network adapter..."
$net = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.DefaultIPGateway -ne $null -and $_.IPEnabled -eq $true } | Select-Object -First 1

if (-not $net) {
    Write-Host "Error: Could not find an active network connection with a gateway." -ForegroundColor Yellow
    exit
}

$gateway = $net.DefaultIPGateway[0]
$ifIndex = $net.InterfaceIndex

$gw_parts = $gateway.Split('.')
$fake_ip = "$($gw_parts[0]).$($gw_parts[1]).$($gw_parts[2]).250"
$fake_mac = "AA-BB-CC-DD-EE-FF"

Write-Host "Adapter Index: $ifIndex" -ForegroundColor Cyan
Write-Host "Gateway IP: $gateway" -ForegroundColor Cyan
Write-Host "Injecting duplicate MAC ($fake_mac) into local ARP table..."

try {
    # Poison the gateway
    netsh interface ipv4 set neighbors $ifIndex $gateway $fake_mac
    
    # Add a second IP with the exact same MAC to create a duplicate
    netsh interface ipv4 set neighbors $ifIndex $fake_ip $fake_mac
    
    Write-Host ""
    Write-Host "ARP Table successfully poisoned!" -ForegroundColor Red
    Write-Host ">>> RUN WIFISHIELD NOW TO DETECT THE ATTACK <<<" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press ENTER when you are done testing to clean up the ARP table..."
    Read-Host
    
    # Cleanup
    Write-Host "Cleaning up ARP table..."
    netsh interface ipv4 delete neighbors $ifIndex $gateway
    netsh interface ipv4 delete neighbors $ifIndex $fake_ip
    Write-Host "Cleanup complete! You are safe." -ForegroundColor Green
    
} catch {
    Write-Host "ERROR: This script MUST be run as Administrator!" -ForegroundColor Red
}

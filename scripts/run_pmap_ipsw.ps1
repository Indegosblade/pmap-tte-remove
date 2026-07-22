$ipsw = 'ipsw'  # Assumes ipsw is on PATH; adjust if needed
$kc_260 = 'kernelcaches/26.0/kernelcache.release.iPhone18,1'
$kc_265 = 'kernelcaches/26.5/kernelcache.release.iPhone18,1'
$out = 'data'

# Try macho info --symbols on the kernelcache
Write-Host "=== 26.0 MACHO SYMBOLS (pmap filter) ==="
& $ipsw macho info $kc_260 -n 2>&1 | Where-Object { $_ -match 'pmap' } | Out-File "$out\pmap_macho_260.txt" -Encoding utf8
$count = (Get-Content "$out\pmap_macho_260.txt" | Measure-Object -Line).Lines
Write-Host "Lines: $count"
if ($count -gt 0 -and $count -lt 100) { Get-Content "$out\pmap_macho_260.txt" }

Write-Host ""
Write-Host "=== 26.5 MACHO SYMBOLS (pmap filter) ==="
& $ipsw macho info $kc_265 -n 2>&1 | Where-Object { $_ -match 'pmap' } | Out-File "$out\pmap_macho_265.txt" -Encoding utf8
$count = (Get-Content "$out\pmap_macho_265.txt" | Measure-Object -Line).Lines
Write-Host "Lines: $count"
if ($count -gt 0 -and $count -lt 100) { Get-Content "$out\pmap_macho_265.txt" }

# Try macho info with fileset entry for AMFI/kernel
Write-Host ""
Write-Host "=== 26.0: fileset entries ==="
& $ipsw macho info $kc_260 -d 2>&1 | Where-Object { $_ -match 'LC_FILESET|entry' } | Select-Object -First 10

Write-Host ""
Write-Host "=== 26.5: fileset entries ==="
& $ipsw macho info $kc_265 -d 2>&1 | Where-Object { $_ -match 'LC_FILESET|entry' } | Select-Object -First 10

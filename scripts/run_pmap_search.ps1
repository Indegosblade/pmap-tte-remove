$ipsw = 'ipsw'  # Assumes ipsw is on PATH; adjust if needed
$kc_260 = 'kernelcaches/26.0/kernelcache.release.iPhone18,1'
$kc_265 = 'kernelcaches/26.5/kernelcache.release.iPhone18,1'

Write-Host "=== 26.0 pmap_remove symbols ==="
& $ipsw kernel sym $kc_260 2>&1 | Where-Object { $_ -match 'pmap' } | Out-File 'data/pmap_syms_260.txt' -Encoding utf8
Get-Content 'data/pmap_syms_260.txt'

Write-Host ""
Write-Host "=== 26.5 pmap_remove symbols ==="
& $ipsw kernel sym $kc_265 2>&1 | Where-Object { $_ -match 'pmap' } | Out-File 'data/pmap_syms_265.txt' -Encoding utf8
Get-Content 'data/pmap_syms_265.txt'

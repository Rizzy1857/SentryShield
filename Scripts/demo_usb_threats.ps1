# Creates a fake "USB" folder with one of each threat type
$demoPath = "C:\SentryShield\DemoUSB"
New-Item -ItemType Directory -Force -Path $demoPath

# 1. High entropy file (simulates encrypted malware)
$random = [byte[]]::new(4096)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
[IO.File]::WriteAllBytes("$demoPath\suspicious_payload.tmp", $random)

# 2. Magic byte mismatch (exe disguised as jpg)
$mz = [byte[]](0x4D, 0x5A) + [byte[]]::new(510)
[IO.File]::WriteAllBytes("$demoPath\invoice_photo.jpg", $mz)

# 3. Clean file (should pass)
Set-Content "$demoPath\readme.txt" "Quarterly maintenance schedule v2"

Write-Host "Demo USB folder ready at $demoPath"
Write-Host "Now scan this folder in SentryShield to see threat detection in action"

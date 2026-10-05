Set-Service -Name sshd -StartupType Manual
Start-Service sshd
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
Write-Host "SSH enabled for testing. Remember to run disable_ssh_test.ps1 when done."
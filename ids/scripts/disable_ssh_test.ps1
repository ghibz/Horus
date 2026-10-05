Stop-Service sshd
Set-Service -Name sshd -StartupType Disabled
Remove-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
Write-Host "SSH disabled and firewall rule removed."
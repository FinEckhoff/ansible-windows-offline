Enable-PSRemoting -Force

Set-Service WinRM -StartupType 'Automatic'

Set-Item -Path 'WSMan:\localhost\Service\Auth\Certificate' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\CredSSP' -Value $true

#$cert = New-SelfSignedCertificate -DnsName $(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname) -CertStoreLocation "cert:\LocalMachine\My"
$cert = New-SelfSignedCertificate -DnsName "XXX INSERT PUBLIC HOSTNAME XXX" -CertStoreLocation "cert:\LocalMachine\My"
#winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname)`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"XXX INSERT PUBLIC HOSTNAME XXX`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

New-NetFirewallRule -DisplayName "Allow WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force
Set-ExecutionPolicy Unrestricted -Force
Restart-Service WinRM

winrm enumerate winrm/config/Listener

<#
	references:
	https://github.com/devopsgroup-io/vagrant-digitalocean
	https://documentation.wazuh.com/current/installation-guide/installing-wazuh-server/wazuh_server_deb.html#wazuh-server-deb
#>
[console]::backgroundcolor="black"
&{
	$wID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	$principal=new-object System.Security.Principal.WindowsPrincipal($wID)
	$admin=[System.Security.Principal.WindowsBuiltInRole]::Administrator
	$isAdmin=$principal.IsInRole($admin)
	if($isAdmin){cls}else{cls;write-host 'ERROR: You need to run this script in an administrative powershell instance' -f red;pause;exit}
}
$apiKeySecure=read-host -assecurestring 'Enter the DigitalOcean API key'
$apiKey=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiKeySecure))
<# UNCOMMENT THIS SECTION TO PRE-INSTALL REQUIRED PACKAGES
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Installing Chocolatey" -f green
set-executionpolicy bypass -scope process -force;iex ((new-object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Installing vagrant" -f green
choco install vagrant -y
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Installing vagrant-digitalocean" -f green
vagrant plugin install vagrant-digitalocean
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Installing openssh" -f green
choco install openssh -y
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
#>
write-host "Defining variables" -f green
$vmName='wazuh'
$random=-join((48..57)+(65..90)|get-random -count 8|%{[char]$_})
$vmFullName="$vmName"
$setupFolder="C:\$vmFullName-SETUP"
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Creating '$setupFolder' if it doesn't already exist" -f green
if(test-path $setupFolder){rm -r -fo $setupFolder|out-null}
mkdir $setupFolder|out-null
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Changing path to '$setupFolder'" -f green
cd $setupFolder
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Generating RSA key" -f green
&'C:\Program Files\OpenSSH-Win64\ssh-keygen.exe' -m PEM -t rsa -f $setupFolder\id_rsa --% -N ""
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Creating the Vagrantfile" -f green
$vagrantFile=@"
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
	config.vm.synced_folder '.','/vagrant',disabled:true
	config.vm.provider :digital_ocean do |provider,override|
		override.ssh.private_key_path='$setupFolder\id_rsa'
		override.vm.box='digital_ocean'
		override.vm.box_url="https://github.com/devopsgroup-io/vagrant-digitalocean/raw/master/box/digital_ocean.box"
		override.nfs.functional=false
		override.vm.hostname='$vmFullName'
		override.vm.define '$vmFullName'
		provider.ssh_key_name='$vmFullName'
		provider.token='$apiKey'
		provider.image='debian-9-x64'
		provider.region='nyc1'
		provider.size='s-4vcpu-8gb'
		provider.ipv6=false
		provider.backups_enabled=false
		provider.name='$vmFullName'
		provider.tags=['wazuh']
	end
	config.vm.provision 'shell',path:'wazuh_digitalocean_setup.sh'
end
"@
[system.io.file]::writealllines("$setupFolder\Vagrantfile",$vagrantFile,[system.text.utf8encoding]($false))
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host 'Creating the VM from the Vagrantfile' -f green
vagrant up --provider=digital_ocean
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Cleaning up '$setupFolder' directory" -f green
cd $PSScriptRoot
rm -r -fo $setupFolder
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host "Deleting ssh key from digitalocean" -f green
$sshKeys=(curl -H @{'Authorization'="Bearer $apiKey"} 'https://api.digitalocean.com/v2/account/keys').content|convertfrom-json
foreach($sshKey in $sshKeys.ssh_keys){
	$sshID=$sshKey.id
	$sshName=$sshKey.name
	if($sshName -eq $vmFullName){
		curl -method delete -H @{'Authorization'="Bearer $apiKey"} "https://api.digitalocean.com/v2/account/keys/$sshID"
		break
	}
}
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
write-host 'Done!' -f green
write-host "Remember to plug the wazuh api into the wazuh app: https://documentation.wazuh.com/current/installation-guide/installing-elastic-stack/connect_wazuh_app.html" -f green
write-host '-----------------------------------------------------------------------------------------------' -f darkgray
pause

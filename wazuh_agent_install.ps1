[console]::backgroundcolor="black"
&{
	$wID=[System.Security.Principal.WindowsIdentity]::GetCurrent();$principal=new-object System.Security.Principal.WindowsPrincipal($wID);$admin=[System.Security.Principal.WindowsBuiltInRole]::Administrator;$isAdmin=$principal.IsInRole($admin)
	if($isAdmin){cls}else{cls;write-host 'ERROR: You need to run this script as admin' -f red;exit}
}
#####################configuration#####################see https://documentation.wazuh.com/current/installation-guide/installing-wazuh-agent/wazuh_agent_windows.html#wazuh-agent-windows
$base_url='' #e.g. https://1.2.3.4:55000
$username='root'
$password=read-host -assecurestring 'Enter the wazuh instance password'
#$password=convertto-securestring $password -asplaintext -force
$agent_name=$env:computername
$path='C:\Program Files (x86)\ossec-agent\'
$config='C:\Program Files (x86)\ossec-agent\ossec.conf'
$wazuh_manager='' #e.g 1.2.3.4
#####################certification#####################
if(-not([System.Management.Automation.PSTypeName]'PolicyCert').type){add-type @"
	using System.Net;using System.Security.Cryptography.X509Certificates;public class PolicyCert:ICertificatePolicy{
		public PolicyCert(){}
		public bool CheckValidationResult(ServicePoint sPoint,X509Certificate cert,WebRequest wRequest,int certProb){return true;}
	}
"@}
[System.Net.ServicePointManager]::CertificatePolicy=new-object PolicyCert #ignore self-signed certs
#####################functions#####################
function apiCall($method,$resource,$params){
	$creds=new-object System.Management.Automation.PSCredential($username,$password)
	$url=$base_url+$resource;
	try{return invoke-webrequest -uri $url -method $method -body $params -credential $creds}catch{return $_.exception}
}
function registerAgent($agentID){
	echo 'Getting agent key'
	$response=apiCall -method 'GET' -resource "/agents/$agentID/key"|convertfrom-json
	if($response.error -ne '0'){echo "ERROR: $($response.message)";exit}
	$agent_key=$response.data
	echo 'Key received... importing'
	echo 'y'|& "$($path)manage_agents.exe" "-i $($agent_key)" "y`r`n"
	echo 'Stopping local wazuh agent'
	stop-service 'OssecSvc'
	sleep -s 10
	echo 'Updating local wazuh agent configuration'
	ac $config "`n<ossec_config>   <client>	  <server-ip>$($wazuh_manager)</server-ip>   </client> </ossec_config>"
	echo 'Restarting local wazuh agent'
	start-service 'OssecSvc'
}
#####################main script#####################
$file='wazuh-agent-3.6.1-1.msi'
$link="https://packages.wazuh.com/3.x/windows/$file"
$local="c:\$file"
echo "Downloading $file installer"
invoke-webrequest -uri $link -outfile $local
echo "Installing $file"
start-process msiexec.exe -argumentlist "/i $local /qn" -wait
del $local
try{echo 'Testing API access';$testResponse=apiCall -method 'GET' -resource '/manager/info?pretty';($testResponse.content|convertfrom-json).data.version
}catch{write-host "The API couldn't be reached..." -f red;exit}
echo 'Checking whether agent already exists'
$agentData=apiCall -method 'GET' -resource '/agents?pretty' -params @{search=$agent_name}|convertfrom-json
$matchingAgentCount=$agentData.data.totalitems
if($matchingAgentCount -lt 1){ #if the agent does not already exist, add it
	echo 'Adding new agent'
	$response=apiCall -method 'POST' -resource '/agents' -params @{name=$agent_name;ip='any'}|convertfrom-json
	if($response.error -ne '0'){echo "ERROR: $($response.message)";exit}
	$agent_id=$response.data.id
	echo "Agent '$agent_name' with ID '$agent_id' added."
	registerAgent $agent_id
}else{ #if the agent already exists, register it
	echo 'Agent already exists'
	$agent_id=$agentData.data.items.id
	registerAgent $agent_id
}

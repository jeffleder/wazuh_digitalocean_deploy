# wazuh_digitalocean_deploy
A handful of scripts to deploy Wazuh into DigitalOcean using NGINX as an SSL/authentication proxy and link Windows agents to the instance (through NGINX) via PowerShell
***
# Files
* **wazuh_digitalocean_setup.ps1**: Run this, supplying your DigitalOcean API key, to deploy Wazuh to DigitalOcean
* **wazuh_digitalocean_setup.sh**: Edit the variables in this script; it will be called by the ps1 script after droplet provisioning
* **wazuh_agent_install.ps1**: Run this on a Windows device to connect it back to the Wazuh instance (through NGINX)
***
# Notes
* Currently, the script is written to deploy Wazuh version 3.6

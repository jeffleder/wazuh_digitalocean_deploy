echo '----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo 'Defining variables' #fill these variables in
regularUser='' #standard user name
regularPass='' #standard user password
rootPass='' #root password
email_to='' #email notification recipient address
email_from='' #email notification sending address
smtp_server='' #email notification smtp server (verified working using option 3 from https://bit.ly/2E4liGK)
echo '-----------------------------------------------------------------------------------------------'
echo 'Setting timezone'
cp /usr/share/zoneinfo/America/Chicago /etc/localtime
echo America/Chicago>/etc/timezone
echo -ne '2\n49\n11\n1\n'|tzselect 2>/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Disabling IPv6'
echo >>/etc/sysctl.conf
echo 'net.ipv6.conf.all.disable_ipv6=1'>>/etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6=1'>>/etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6=1'>>/etc/sysctl.conf
echo '-----------------------------------------------------------------------------------------------'
echo 'Disabling GRUB recovery options'
sed -i.bak 's/#GRUB_DISABLE_RECOVERY="true"/GRUB_DISABLE_RECOVERY="true"/' /etc/default/grub
update-grub
echo '-----------------------------------------------------------------------------------------------'
echo 'Configuring pre-login IP display'
echo '\4'>>/etc/issue
echo '-----------------------------------------------------------------------------------------------'
echo "Adding '$regularUser' user"
adduser $regularUser --gecos ',,,' --disabled-password
echo -ne '$regularPass\n$regularPass\n'|passwd $regularUser
echo '-----------------------------------------------------------------------------------------------'
echo 'Updating root password'
echo -ne '$rootPass\n$rootPass\n'|sudo passwd root
echo '-----------------------------------------------------------------------------------------------'
echo 'Preventing apt-get from displaying dpkg-reconfigure error'
export DEBIAN_FRONTEND=noninteractive
echo '-----------------------------------------------------------------------------------------------'
echo 'Updating system packages'
apt-get -y -qq update >/dev/null
apt-get -y -qq upgrade >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing wazuh dependencies'
apt-get -y -qq install curl >/dev/null
apt-get -y -qq install apt-transport-https >/dev/null
apt-get -y -qq install lsb-release >/dev/null
apt-get -y -qq install software-properties-common >/dev/null
apt-get -y -qq install wget >/dev/null
apt-get -y -qq install apache2-utils >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Creating python symlink'
if [ ! -f /usr/bin/python ]; then ln -s /usr/bin/python3 /usr/bin/python; fi
echo '-----------------------------------------------------------------------------------------------'
echo 'Adding wazuh GPG key and apt repository'
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing wazuh-manager'
apt-get -y -qq install wazuh-manager=3.6.1-1 >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Adding nodejs repository'
curl -sL https://deb.nodesource.com/setup_8.x | bash -
apt-get update >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing nodejs'
apt-get -y -qq install nodejs >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing wazuh-api'
apt-get -y -qq install wazuh-api=3.6.1-1 >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Setting wazuh-api credentials'
htpasswd -b -c /var/ossec/api/configuration/auth/user root $rootPass
echo '-----------------------------------------------------------------------------------------------'
echo 'Generating wazuh-api ssl cert'
echo -ne 'US\nSTATE\nCITY\nORGANIZATION\nUNIT\nCOMMON\nEMAIL@DOMAIN.COM\n\n\n'|openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /var/ossec/api/configuration/ssl/server.key -out /var/ossec/api/configuration/ssl/server.crt
echo '-----------------------------------------------------------------------------------------------'
echo 'Updating wazuh-api configuration for ssl'
sed -i 's|config.https = "no"|config.https = "yes"|' /var/ossec/api/configuration/config.js
sed -i 's|//config.https_key|config.https_key|' /var/ossec/api/configuration/config.js
sed -i 's|//config.https_cert|config.https_cert|' /var/ossec/api/configuration/config.js
echo '-----------------------------------------------------------------------------------------------'
echo 'Restarting wazuh-api'
systemctl restart wazuh-api
echo '-----------------------------------------------------------------------------------------------'
echo 'Adding elastic GPG key and apt repository'
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-6.x.list
apt-get update >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing filebeat'
apt-get -y -qq install filebeat=6.4.0 >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Downloading filebeat config file from the wazuh repository'
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/filebeat/filebeat.yml
echo '-----------------------------------------------------------------------------------------------'
echo 'Editing /etc/filebeat/filebeat.yml to point to the elastic stack'
sed -i.bak 's/YOUR_ELASTIC_SERVER_IP/localhost/' /etc/filebeat/filebeat.yml
echo '-----------------------------------------------------------------------------------------------'
echo 'Enabling/starting filebeat service'
systemctl daemon-reload
systemctl enable filebeat.service
systemctl start filebeat.service
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing default-jre'
apt-get -y -qq install default-jre >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing elasticsearch'
apt-get -y -qq install elasticsearch=6.4.0 >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Tuning elasticsearch'
sed -i 's|#bootstrap.memory_lock: true|bootstrap.memory_lock: true|' /etc/elasticsearch/elasticsearch.yml
sed -i 's|#MAX_LOCKED_MEMORY=unlimited|MAX_LOCKED_MEMORY=unlimited|' /etc/default/elasticsearch
sed -i 's|-Xms1g|-Xms4g|' /etc/elasticsearch/jvm.options
sed -i 's|-Xmx1g|-Xmx4g|' /etc/elasticsearch/jvm.options
mkdir -p /etc/systemd/system/elasticsearch.service.d/
cat>/etc/systemd/system/elasticsearch.service.d/elasticsearch.conf<<_EOF_
[Service]
LimitMEMLOCK=infinity
_EOF_
echo '-----------------------------------------------------------------------------------------------'
echo 'Enabling/starting elasticsearch service'
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
echo '-----------------------------------------------------------------------------------------------'
echo 'Waiting for elasticsearch to start'
while ! curl -s localhost:9200;do echo 'Waiting for elasticsearch to start';sleep 3;done
echo '-----------------------------------------------------------------------------------------------'
echo 'Downloading elasticsearch wazuh configuration'
curl https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/elasticsearch/wazuh-elastic6-template-alerts.json | curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing logstash'
apt-get -y -qq install logstash=1:6.4.0-1 >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Downloading logstash wazuh configuration'
curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/logstash/01-wazuh-local.conf
echo '-----------------------------------------------------------------------------------------------'
echo 'Adding logstash user to ossec group'
usermod -a -G ossec logstash
echo '-----------------------------------------------------------------------------------------------'
echo 'Enabling/starting logstash service'
systemctl daemon-reload
systemctl enable logstash.service
systemctl start logstash.service
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing kibana'
apt-get -y -qq install kibana=6.4.0 >/dev/null
# echo '-----------------------------------------------------------------------------------------------'
# echo 'Updating kibana configuration to exclude developer console and timelion'
# echo ''>>/etc/kibana/kibana.yml
# echo 'console.enabled: false #hide developer console'>>/etc/kibana/kibana.yml
# echo 'timelion.enabled: false #hide timelion'>>/etc/kibana/kibana.yml
echo '-----------------------------------------------------------------------------------------------'
echo 'Increasing nodejs heap memory limit (to prevent out-of-memory errors)'
export NODE_OPTIONS="--max-old-space-size=3072"
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing wazuh kibana plugin/app'
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.6.1_6.4.0.zip
echo '-----------------------------------------------------------------------------------------------'
echo 'Enabling/starting kibana service'
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
echo '-----------------------------------------------------------------------------------------------'
echo 'Disabling the elasticsearch repository to prevent upgrades from breaking ELK'
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/elastic-6.x.list
apt-get update >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Installing nginx'
apt-get -y -qq install nginx >/dev/null
echo '-----------------------------------------------------------------------------------------------'
echo 'Generating nginx ssl cert'
mkdir -p /etc/ssl/certs /etc/ssl/private
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/private/kibana-access.key -out /etc/ssl/certs/kibana-access.pem
echo '-----------------------------------------------------------------------------------------------'
echo 'Configuring nginx as an https reverse proxy to kibana'
cat>/etc/nginx/sites-available/default<<_EOF_
server {
    listen 80;
    listen [::]:80;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 default_server;
    listen [::]:443;
    ssl on;
    ssl_certificate        /etc/ssl/certs/kibana-access.pem;
    ssl_certificate_key    /etc/ssl/private/kibana-access.key;
    access_log             /var/log/nginx/nginx.access.log;
    error_log              /var/log/nginx/nginx.error.log;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
        proxy_pass http://localhost:5601/;
    }
}
_EOF_
echo '-----------------------------------------------------------------------------------------------'
echo 'Generating .htpasswd file'
htpasswd -b -c /etc/nginx/conf.d/kibana.htpasswd root $rootPass
echo '-----------------------------------------------------------------------------------------------'
echo 'Restarting nginx to save changes'
systemctl restart nginx
echo '-----------------------------------------------------------------------------------------------'
echo 'Configuring alerts'
sed -i 's/<email_notification>no<\/email_notification>/<email_notification>yes<\/email_notification>/' /var/ossec/etc/ossec.conf
sed -i 's/<email_to>recipient@example.wazuh.com<\/email_to>/<email_to>$email_to<\/email_to>/' /var/ossec/etc/ossec.conf
sed -i 's/<email_from>ossecm@example.wazuh.com<\/email_from>/<email_from>$email_from<\/email_from>/' /var/ossec/etc/ossec.conf
sed -i 's/<smtp_server>smtp.example.wazuh.com<\/smtp_server>/<smtp_server>$smtp_server<\/smtp_server>/' /var/ossec/etc/ossec.conf
sed -i 's/<email_alert_level>12<\/email_alert_level>/<email_alert_level>8<\/email_alert_level>/' /var/ossec/etc/ossec.conf
echo '----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo 'Installing perl-modules for vagrant user cleanup'
apt-get -y -qq install perl-modules >/dev/null
echo '----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo 'Reconfiguring /etc/crontab to use /bin/bash instead of /bin/sh'
echo 'SHELL=/bin/bash'>/etc/crontab.tmp
tail -n+8 /etc/crontab>>/etc/crontab.tmp
cat /etc/crontab.tmp>/etc/crontab
rm -f /etc/crontab.tmp
echo '----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo 'Creating runonce script with self-deleting crontab entry'
cat>/root/runonce.sh<<_EOF_
#!/bin/bash
echo \$(date)' - deleting crontab entry for runonce script'
head -n-1 /etc/crontab>>/etc/crontab.tmp;cat /etc/crontab.tmp>/etc/crontab;rm -f /etc/crontab.tmp
echo \$(date)' - deleting vagrant user'
deluser --remove-all-files vagrant
rm -f /etc/sudoers.d/vagrant
echo \$(date)' - removing openssh-server'
apt-get -y purge openssh-server
echo \$(date)' - reinstalling openssh-server'
apt-get -y install openssh-server
echo \$(date)' - done!'
_EOF_
chmod 700 /root/runonce.sh
echo '*  *    * * *   root    /root/runonce.sh&>>/root/runonce.log'>>/etc/crontab
echo '-----------------------------------------------------------------------------------------------'
echo 'Rebooting to complete install'
reboot

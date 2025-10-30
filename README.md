# ZTE-VDSL-Zabbix
Automated retrieval of DSL statistics from ZTE H267A or other compatible router and Zabbix integration

This project automates the retrieval of VDSL/DSL statistics from ZTE routers (tested with H267A) through their web interface — without TR-069 or Telnet.
It reverse-engineers the ZTE web login and data pages using curl, auto-detects the correct endpoints, and outputs DSL stats as JSON for ingestion by Zabbix or other monitoring system.

# Features
Automatic login

Detection of DSL data endpoints

JSON output

Zabbix sender

# Prerequisites
linux e.g. Ubuntu, rpi3 with raspbian, etc

curl

python

zabbix server (tested with 7.0)

zabbix sender


# How to use
copy the push_modem.sh and zte_vdsl.py scripts to your linux machine (default path /mnt/zte) that has access to your ZTE VDSL router

Edit push_modem.sh (credentials, IP, etc)

Add push_modem.sh to crontab (* * * * * /mnt/zte/push_modem.sh > /dev/null 2>&1)

Import zabbix template (zbx_zte_vdsl.json)

Add your ZTE router to Zabbix and link it to the template

# ZTE-VDSL-Zabbix
Automated retrieval of DSL statistics from ZTE H267A or other compatible router and Zabbix integration

This project automates the retrieval of VDSL/DSL statistics from ZTE routers (tested with H267A) through their web interface — without TR-069 or Telnet.
It reverse-engineers the ZTE web login and data pages using curl, auto-detects the correct endpoints, and outputs DSL stats as JSON for ingestion by Zabbix or other monitoring system.

# Features
Automatic login

Detection of DSL data endpoints (/common_page/internet_dsl_interface_lua.lua, etc.)

JSON output

Zabbix sender

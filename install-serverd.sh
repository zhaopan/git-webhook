#!/bin/bash

systemctl daemon-reload
systemctl start webhook-handler
systemctl restart webhook-handler
systemctl status webhook-handler
#systemctl enable webhook-handler

# log
#journalctl -u webhook-handler -f

# stop & uninstall
# systemctl stop webhook-handler
# systemctl disable webhook-handler

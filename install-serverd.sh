#!/bin/bash

systemctl daemon-reload
systemctl start webhook-handler
systemctl status webhook-handler
#systemctl enable webhook-handler

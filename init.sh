#!/bin/bash

# 初始化网络
docker network create --subnet=172.18.0.0/16 backend

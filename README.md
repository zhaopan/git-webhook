# webhook

## `gogs webhook handler`

## init

```bash
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct

chmod +x init.sh
sh init.sh

chmod +x install-serverd.sh
sh install-serverd.sh
```

## mod

```bash
go mod init zhaopan/x/webhook
go mod tidy
go mod vendor
```

## build + run

```bash
go build .
go run .
```

## build | run | stop

```bash
# build
make all

# run
make run

# stop
make down
```

## config

- dir-root: `/mnt/www/`
- applications: `config.json`

## nginx.conf

用于从容器内部访问宿主机

```yml
services:
  nginx:
    ...
+    extra_hosts:
+      - "host.docker.internal:host-gateway"
+    networks:
+      backend:
+        ipv4_address: ${NGINX_IP}
```

proxy

`nginx/conf.d/webhook.conf`

```yml
server {
    listen 443 ssl http2;
+    server_name <webhook.github.com>;
+    ssl_certificate ssl/github.com.crt;
+    ssl_certificate_key ssl/github.com.key;
    # HSTS 安全头
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
+        proxy_pass http://host.docker.internal:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    # 调整上传文件大小限制（按需修改）
    client_max_body_size 50m;
}
```

## install service

OS: `debian`

```bash
# build
go build -o webhook-handler -mod=vendor

# run test
./webhook-handler

# PATH
root@linux:~# which pnpm
/root/.nvm/versions/node/v22.15.1/bin/pnpm
root@linux:~# which git
/usr/bin/git

# 将git和pnpm的路径写入到 webhook-handler.service . Environment

# 一旦修改了 webhook-handler.service 就要刷新服务

# serverd conf
cp webhook-handler.service /etc/systemd/system/webhook-handler.service

# install linux serverd
chmod +x install-serverd.sh
sh install-serverd.sh
```

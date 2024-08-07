---
title: foundry使用一
date: 2023-12-15 15:34:13
tags: [区块链安全, 区块链工具]
categories: 区块链工具
description: 摘要：foundry的docker环境搭建
---

# 1. Foundry环境搭建：

## 1.1 拉取`Foundry` 镜像

```docker
docker pull ghcr.io/foundry-rs/foundry:latest
```

## 1.2 以sh形式，创建一个新的容器，并运行对应的容器

```docker
sudo docker run -d -v /local_dir:/docker_dir -it --name new_name image_name /bin/sh
```

- `-d`：让容器在后台运行
- `-v`：用以挂载卷
- `-it`：用交互模式运行容器，并分配一个伪终端
- `--name` ：给容器命名

## 1.3 查看容器的是否运行，以及容器id

```docker
sudo docker ps
```

## 1.4 进行容器交互界面

```docker
sudo docker exec -it containerID/name /bin/sh
```

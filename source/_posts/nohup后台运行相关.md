---
title: nohup后台运行相关
date: 2024-04-15 22:59:08
tags: [服务器, linux工具]
categories:
  - [linux]
  - [服务器]
description: 摘要：nohup后台运行相关
---

## 1. nohup和&

用途：ssh连接linux服务器的时候，终端可能会断开，如何让程序在服务器后台一直运行

- nohup：nohup运行指令，使程序可以忽略刮起继续运行
- &：让程序在后台运行，一般和nohup一起用

nohup command &

nohup：是让命令永久的执行下去，和用户终端没有关系，&是命令后台运行的意思

## 2. 输出重定向

命令在后台运行的时候，可以把输出重定向到某个文件中，相当于一个日志文件，记录运行过程中的数据

```
nohup command > output.file 2>&1 &
```

输出的内容保存到output.file中

0 – stdin (standard input)，1 – stdout (standard output)，2 – stderr (standard error) ；
2>&1是将标准错误（2）重定向到标准输出（&1），标准输出（&1）再被重定向输入到out.file文件中。

## 3.nohup后台相关

1. jobs -l

```
jobs -l
//查看当前终端生效的nohup程序，其它终端的命令，利用ps
```

2. ps查看后台nohup

```
ps -aux | grep <test>
//查看后台运行的nohup，以及自己运行的程序
```

3. kill关闭对应nohup

```
kill -9 <进程号>
//关掉对应的进程
netstat -ap | grep port
//通过对应的端口，查看相应的进程
netstat -nap | grep PID
//通过相应的进城ID,查看其占用的端口
```




















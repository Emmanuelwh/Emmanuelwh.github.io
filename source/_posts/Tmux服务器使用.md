---
title: Tmux服务器使用
date: 2023-12-16 11:10:30
tags: [服务器, linux工具]
categories: 
  - [linux]
  - [服务器]
description: 摘要：Tmux实现服务器会话分离
---

# Tmux是干什么的？
## 会话与进程
在一个终端中，通过命令行的形式与计算机系统进行交互的方式，称为一个session"会话"。
一个典型的例子：通过ssh登陆远程服务器，在服务器跑代码，运行命令的时候，如果ssh连接服务终止的话，那么这个代码、命令的运行也就随即终止了。
即ssh窗口和会话里的进程是相绑定的。

之前一直懒得解决这个问题，就电脑一直开着在vscode，或者shell软件里面跑着代码qwq，今天实在忍不了了，去搜了一下，用tmux解决了这个问题。
## tmux
tmux是一个将会话和窗口的“解绑”工具，将其彻底分离
其对我而言主要功能如下：
```
1. 允许在单个窗口中，同时运行多个命令行程序，互不影响
2. 让新窗口随时接入、查看已经存在的会话（不同电脑都可以看）
3. 最重要的一点qwq：ssh断了，网断了，也不影响程序跑
```
# tmux最实用的语法
## 1. 新建会话
```linux
tmux new -s <session_name>
新建一个会话，给它起个名，之后就用这个连接
```
## 2. 分离会话，从当前会话推出
```linux
tmux detach  （ctrl +b   、  d）
```
## 3. 查看当前所有的会话
```linux
tmux ls
```
## 4. 接入某个运行的会话
```linux
tmux attach -t <session-name>
```
## 5. 关闭某个会话
```linux
tmux kiss-session -t <session-name>
```
## 6.不常用语法
```linux
## 切换会话
tmux switch -t <session-name>
## 重命名会话
tmux rename-session -t <old-name>  <new-name>
```
# 更多其它操作可见这个博客
[tmux更多用法](https://blog.csdn.net/sasa0906/article/details/121132338?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522169768574316800192242868%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=169768574316800192242868&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-4-121132338-null-null.142^v96^pc_search_result_base7&utm_term=tmux%E5%A6%82%E4%BD%95%E9%80%80%E5%87%BA&spm=1018.2226.3001.4187)

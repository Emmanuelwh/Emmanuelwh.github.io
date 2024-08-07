---
title: Vue+Django前后端交互跨域
date: 2023-12-16 11:13:13
tags: 前后端
categories: 前后端
description: 摘要：vue+Django解决前后端跨域问题
---

# Vue+Django前后端开发
当我们从零开始利用Vue和Django开发的时候，就会遇到跨域问题，一般来说Vue本地端口可以是8080或者其它，Django的本地端口一般是8000。
虽然在Vue中我们用axios 向8000端口发送http请求，但还是收到跨域访问的限制
这里分别从前后端说明该如何配置，解决跨域问题
## 前端Vue配置
### 1. config/index.js
基于封装好的axios来进行跨域
在前端config/index.js中,设置proxy进行跨域
```js

module.exports = {
    devServer:{
      proxy:{
        '/api':{//表示拦截以/api开头的请求路径
          target:'http://127.0.0.1:8000',
          changOrigin: true,//是否开启跨域
          pathRewrite:{
            '^/api':'' //重写api，把api变成空字符，因为我们真正请求的路径是没有api的
          }
        }
      }
    }
}
```
### 2. axios的封装文件
建立一个json文件，对axios.create进行封装的时候，将其baseURL设置为api，如下所示
```js
const http = axios.create({
  baseURL: '/api',
  timeout: 50000
})
```
## 后端Django配置
### 1. 安装django-cors-headers库
在python环境下直接pip install 进行安装
### 2. 设置setting.py文件
在setting.py中，在INSTALLED_APPS中添加跨域所需的APP`corsheaders`,同时在MIDDLEWARE中也添加响应的中间件，并将允许跨域请求的请求方式进行设置，设置为ALL
```python
INSTALLED_APPS = [
    ......
    'corsheaders',
    ......
]

MIDDLEWARE = [
    ......
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    ......
]

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
```
如果前后端都进行了这样的设置之后，应该前后端就能够进行数据的交互了！

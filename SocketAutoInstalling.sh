#!/bin/bash

function ExternalEnv(){
	# 系统信息获取
	getLinuxOSRelease
	getLinuxOSVersion
	OSVersionCheck
	checkCPU
	checkArchitecture
	
	# 判断Shell命令头
	[[ -z $(echo $SHELL|grep zsh) ]] && osSystemShell="bash" || osSystemShell="zsh"
	
	# 字体颜色
	red(){
		echo -e "\033[31m\033[01m$1\033[0m"
	}
	green(){
		echo -e "\033[32m\033[01m$1\033[0m"
	}
	yellow(){
		echo -e "\033[33m\033[01m$1\033[0m"
	}
	blue(){
		echo -e "\033[34m\033[01m$1\033[0m"
	}
	bold(){
		echo -e "\033[1m\033[01m$1\033[0m"
	}

}

# 检测Linux系统发行版本
function getLinuxOSRelease(){
    if [[ -f /etc/redhat-release ]]; then
        osRelease="centos"
        osSystemPackage="yum"
    elif cat /etc/issue | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
    elif cat /proc/version | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
    fi
}

# 检测系统版本号
function getLinuxOSVersion(){
    if [[ -s /etc/redhat-release ]]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
    else
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/issue)
    fi

    # https://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script

    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        source /etc/os-release
        osInfo=$NAME
        osReleaseVersionNo=$VERSION_ID

        if [ -n $VERSION_CODENAME ]; then
            osReleaseVersionCodeName=$VERSION_CODENAME
        fi
	
    elif type lsb_release >/dev/null 2>&1; then
        # linuxbase.org
        osInfo=$(lsb_release -si)
        osReleaseVersionNo=$(lsb_release -sr)
	
    elif [ -f /etc/lsb-release ]; then
        # For some versions of Debian/Ubuntu without lsb_release command
        . /etc/lsb-release
        osInfo=$DISTRIB_ID
        osReleaseVersionNo=$DISTRIB_RELEASE
	
    elif [ -f /etc/debian_version ]; then
        # Older Debian/Ubuntu/etc.
        osInfo=Debian
        osReleaseVersion=$(cat /etc/debian_version)
        osReleaseVersionNo=$(sed 's/\..*//' /etc/debian_version)
	
    elif [ -f /etc/redhat-release ]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
	
    else
        # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
        osInfo=$(uname -s)
        osReleaseVersionNo=$(uname -r)
    fi
}

# 检查处理器品牌
function checkCPU(){
	osCPUText=$(cat /proc/cpuinfo | grep vendor_id | uniq)
	if [[ $osCPUText =~ "GenuineIntel" ]]; then
		osCPU="intel"
    else
        osCPU="amd"
    fi
}

# 检测架构版本
function checkArchitecture(){
	# https://stackoverflow.com/questions/48678152/how-to-detect-386-amd64-arm-or-arm64-os-architecture-via-shell-bash

	case $(uname -m) in
		i386)   osArchitecture="386" ;;
		i686)   osArchitecture="386" ;;
		x86_64) osArchitecture="amd64" ;;
		arm)    dpkg --print-architecture | grep -q "arm64" && osArchitecture="arm64" || osArchitecture="arm" ;;
		* )     osArchitecture="arm" ;;
	esac
}

# 安装依赖软件
function InstallDependentSoftware(){
	green " 安装依赖软件..."
	$osSystemPackage install -y curl wget tar net-tools
}

# 系统版本检查
function OSVersionCheck(){

    if [ "$osRelease" == "centos" ]; then
        if  [[ ${osReleaseVersionNo} == "6" || ${osReleaseVersionNo} == "5" ]]; then
            green " =================================================="
            red " 本脚本不支持 Centos 6 或 Centos 6 更早的版本"
            green " =================================================="
            exit
        fi

    elif [ "$osRelease" == "ubuntu" ]; then
        if  [[ ${osReleaseVersionNo} == "14" || ${osReleaseVersionNo} == "12" ]]; then
            green " =================================================="
            red " 本脚本不支持 Ubuntu 14 或 Ubuntu 14 更早的版本"
            green " =================================================="
            exit
        fi
        
    elif [ "$osRelease" == "debian" ]; then
        $osSystemPackage update -y
    fi

}

# 安装V2ray
function InstallV2ray(){
	green " =================================================="
	green " 开始安装V2ray"
	green " =================================================="
	
	green " 安装可执行文件"
	${osSystemShell} <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
	green " 更新 geoip.dat 和 geosite.dat 资料档"
	${osSystemShell} <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-dat-release.sh)

	green " =================================================="
	green " V2ray安装完成,启动V2ray..."
	green " =================================================="
	systemctl start v2ray
	green " 验证安装..."
	netstat -anp | grep v2ray &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" V2ray安装失败..."
		Error
    fi
	green " PASS"
	green " 将V2ray加入自启动项"
	green " =================================================="
	systemctl enable v2ray
	green " =================================================="
	green " 安装完成!"
	green " =================================================="
}

# 编译安装Nginx
function InstallNginx(){
	green " =================================================="
	green " Nginx安装准备..."
	green " =================================================="
	sleep 2s
	yum install -y pcre-devel zlib-devel perl gcc
	
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 依赖组件安装失败...请检查网络连接"
		Error
	fi
	
	green " =================================================="
	green " 检测OpenSSL版本"
	green " =================================================="
	OpenSSLVersion=$(expr substr "$(/usr/local/bin/openssl version)" 9 6)
	if [ -z $OpenSSLVersion ]; then
		red " =================================================="
        echo " 未在本机检测到OpenSSL"
		red " =================================================="
		InstallOpenSSL
    fi
	OpenSSLVersionNUM=$(echo $OpenSSLVersion | tr -cd "[0-9]" )		
	if [[ "111" > "$OpenSSLVersionNUM" ]]; then
        green " =================================================="
		green " OpenSSL需要更新"
		green " =================================================="
		InstallOpenSSL
    fi
	cd /usr/local
	green " =================================================="
	green " 开始下载Nginx源码..."
	green " =================================================="
	wget https://nginx.org/download/nginx-1.21.1.tar.gz
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 下载失败...请检查网络连接"
		Error
	fi
	tar -xvzf nginx-1.21.1.tar.gz
	cd /usr/local/nginx-1.21.1
	./configure --with-http_ssl_module --with-http_v2_module
	green " =================================================="
	green " 开始编译并安装Nginx..."
	green " =================================================="
	make
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 编译失败...请查看日志"
		Error
	fi
	make install
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 安装失败...请查看日志"
		Error
	fi
	green " =================================================="
	green " Nginx安装完成"
	green " =================================================="
	cat > "/lib/systemd/system/nginx.service" <<-EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
	green " =================================================="
	green " 正在处理Nginx事项..."
	green " =================================================="
	sed -i 's/\#pid        logs\/nginx.pid;/pid        \/run\/nginx.pid;/g' /usr/local/nginx/conf/nginx.conf
	systemctl daemon-reload
	ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
	ln -s /usr/local/nginx/conf/ /etc/nginx
	green " =================================================="
	green " 启动Nginx..."
	green " =================================================="
	systemctl start nginx.service
	green " 验证安装..."
	netstat -anp | grep nginx &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Nginx启动失败..."
		Error
    fi
	green " PASS"
	green " =================================================="
	green " 将Nginx加入自启动项"
	green " =================================================="
	systemctl enable nginx.service
	green " =================================================="
	green " 安装完成!"
	green " =================================================="

}

# 编译安装OpenSSL
function InstallOpenSSL(){
    green " =================================================="
	green " 开始安装OpenSSL"
	green " =================================================="
	sleep 6s
	yum remove -y openssl
	cd /usr/local
	green " =================================================="
	green " 开始下载OpenSSL源码..."
	green " =================================================="
	wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 下载失败...请检查网络连接"
		Error
	fi
	tar -xvzf openssl-1.1.1k.tar.gz
	cd openssl-1.1.1k
	./Configure
	./config
	green " =================================================="
	green " 开始编译并安装OpenSSL..."
	green " =================================================="
	make
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 编译失败...请查看日志"
		Error
	fi
	make test
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 编译测试未通过...请重试"
		Error
	fi
	make install
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 安装失败...请查看日志"
		Error
	fi
	mv /usr/bin/openssl /usr/bin/openssl-old
	ln -s /usr/local/bin/openssl /usr/bin/openssl
	OpenSSLVersion=$(expr substr "$(/usr/local/bin/openssl version)" 9 6)
	green " =================================================="
	green " OpenSSL版本:   ${OpenSSLVersion}"
	green " =================================================="
}

# V2ray调整配置
function SetV2rayConfig(){

	green " =================================================="
	green " 开始配置V2ray,停止相关服务..."
	green " =================================================="
	systemctl stop v2ray
	systemctl stop nginx.service

	cat > "/usr/local/etc/v2ray/config.json" <<-EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$NewUUID",
						"level": 0
                    }
                ],
				"decryption": "none",
				"fallbacks": [
                    {
					    "alpn": "",
						"path": "",
                        "dest": 80,
						"xver": 0
                    },
                    {
                        "path": "/vws",
                        "dest": 8080,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
				"security": "tls",
                "tlsSettings": {
				    "alpn": [
                        "http/1.1"
                    ],
					"certificates": [
                        {
                            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
                            "keyFile": "/etc/ssl/v2ray/privkey.pem"
                        }
					]
                }
            }
        },
		{
            "port": 8080,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$NewUUID",
                        "level": 0
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/vws"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ],
    "levels": {
        "0": {
            "bufferSize": 10240
        }
    }
}
EOF
	green " =================================================="
	green " 配置完成,等待Nginx服务上线..."
	green " =================================================="
	
	green " =================================================="
	green " 配置Nginx"
	green " =================================================="

	cat > "/usr/local/nginx/conf/nginx.conf" <<-EOF
# 关于配置的更多信息，请参见官方英文文档: http://nginx.org/en/docs/

#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

pid        /run/nginx.pid;


events {
    worker_connections 1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        listen       [::]:80;
        server_name  $Domain;
		# 如通过http协议访问则自动跳转https协议
		# rewrite ^(.*)$ https://$host$1 permanent;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }

# 启用TLS的服务器设置
# 注意：由于使用Certbot自动续订TLS安全证书，此功能即便未使用但也不可关闭。

    server {
        listen       453 ssl http2;
        listen       [::]:453 ssl http2;
        server_name  $Domain;
		
        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        ssl_certificate "/etc/letsencrypt/live/$Domain/fullchain.pem";
        ssl_certificate_key "/etc/letsencrypt/live/$Domain/privkey.pem";
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout  1440m;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
		ssl_session_tickets off;
		ssl_protocols TLSv1.3 TLSv1.2;
		ssl_prefer_server_ciphers off;
		add_header Strict-Transport-Security "max-age=63072000" always;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}

    # 由于在V2ray中启用了acceptProxyProtocol所以不再使用Nginx对WebSocket的反向代理
    #		location /vws {
			# WebSocket协商失败时返回404
    #    		if ($http_upgrade != "websocket") {
    #        		return 404;
    #    		}
    #    		proxy_redirect off;
    #    		proxy_pass http://127.0.0.1:8800;
    #    		proxy_http_version 1.1;
    #    		proxy_set_header Upgrade $http_upgrade;
    #    		proxy_set_header Connection "upgrade";
    #    		proxy_set_header Host $host;
    		# Show real IP in v2ray access.log
    #    		proxy_set_header X-Real-IP $remote_addr;
    #    		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #  		}
    }


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}
}
EOF
	green " =================================================="
	green " 配置完成,重启服务中..."
	green " =================================================="
	systemctl start nginx.service
	systemctl start v2ray
	
	green " 验证..."
	netstat -anp | grep nginx &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Nginx启动失败...请查看日志"
		Error
    fi
	
	netstat -anp | grep v2ray &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" V2ray启动失败...请查看日志"
		Error
    fi
	
	SockerConfig1=' Vless over TCP with TLS , 端口:443 '
	SockerConfig2=' Vless over WebSocker with TLS , 端口:443 , Path : /xws '
	
	green " =================================================="
	green " PASS"
	green " =================================================="

}

# Xray调整配置
function SetXrayConfig(){
	green " =================================================="
	green " 开始配置Xray,停止相关服务..."
	green " =================================================="
	
	systemctl stop xray
	systemctl stop nginx.service
	
	cat > "/usr/local/etc/xray/config.json" <<-EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            //第一通讯协议(VLESS over TCP with XTLS)
			"port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$NewUUID", 
                        "flow": "xtls-rprx-direct",
                        "level": 0
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 6080, // 第一回落点: Xray 的 Trojan 协议
                        "xver": 1
                    },
                    {
                        "path": "/xws", // 第二回落点: websocker协议
                        "dest": 6180,
                        "xver": 1
                    },
                    {
                        "path": "/xltt", // 第三回落点: vmesstcp
                        "dest": 6280,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/xray/fullchain.pem", // 换成你的证书，绝对路径
                            "keyFile": "/etc/ssl/xray/privkey.pem" // 换成你的私钥，绝对路径
                        }
                    ]
                }
            }
        },
        {
            "port": 6080, //第一回落点
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$Password", // 填写你的密码
                        "level": 0
                    }
                ],
                "fallbacks": [
                    {
                        "dest": 80 // 第一回落点的回落点
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true
                }
            }
        },
        {
            "port": 6180, //第二回落点
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$NewUUID", // 填写你的 UUID
                        "level": 0
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true, // 提醒：若你用 Nginx/Caddy 等反代 WS，需要删掉这行
                    "path": "/xws" // 必须换成自定义的 PATH，需要和分流的一致
                }
            }
        },
        {
            "port": 6280, //第三回落点
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$NewUUID", // 填写你的 UUID
                        "level": 0
                    }
                ],
				"decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
				    "alpn": [
                        "http/1.1"
                    ],
					"certificates": [
                        {
                            "certificateFile": "/etc/ssl/xray/fullchain.pem",
                            "keyFile": "/etc/ssl/xray/privkey.pem"
                        }
					]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ],
    "levels": {
        "0": {
            "bufferSize": 10240
        }
    }
}
EOF
	green " =================================================="
	green " 配置完成,等待Nginx服务上线..."
	green " =================================================="
	
	cat > "/usr/local/nginx/conf/nginx.conf" <<-EOF
# 关于配置的更多信息，请参见官方英文文档: http://nginx.org/en/docs/

#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

pid        /run/nginx.pid;


events {
    worker_connections 1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        listen       [::]:80;
        server_name  $Domain;
		# 如通过http协议访问则自动跳转https协议
		# rewrite ^(.*)$ https://$host$1 permanent;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }

# 启用TLS的服务器设置
# 注意：由于使用Certbot自动续订TLS安全证书，此功能即便未使用但也不可关闭。

    server {
        listen       453 ssl http2;
        listen       [::]:453 ssl http2;
        server_name  $Domain;
		
        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        ssl_certificate "/etc/letsencrypt/live/$Domain/fullchain.pem";
        ssl_certificate_key "/etc/letsencrypt/live/$Domain/privkey.pem";
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout  1440m;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
		ssl_session_tickets off;
		ssl_protocols TLSv1.3 TLSv1.2;
		ssl_prefer_server_ciphers off;
		add_header Strict-Transport-Security "max-age=63072000" always;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}

    # 由于在V2ray中启用了acceptProxyProtocol所以不再使用Nginx对WebSocket的反向代理
    #		location /vws {
			# WebSocket协商失败时返回404
    #    		if ($http_upgrade != "websocket") {
    #        		return 404;
    #    		}
    #    		proxy_redirect off;
    #    		proxy_pass http://127.0.0.1:8800;
    #    		proxy_http_version 1.1;
    #    		proxy_set_header Upgrade $http_upgrade;
    #    		proxy_set_header Connection "upgrade";
    #    		proxy_set_header Host $host;
    		# Show real IP in v2ray access.log
    #    		proxy_set_header X-Real-IP $remote_addr;
    #    		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #  		}
    }


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}
}
EOF
	green " =================================================="
	green " 配置完成,重启服务中..."
	green " =================================================="
	systemctl start nginx.service
	systemctl start xray
	
	green " 验证..."
	netstat -anp | grep nginx &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Nginx启动失败...请查看日志"
		Error
    fi
	
	netstat -anp | grep xray &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Xray启动失败...请查看日志"
		Error
    fi
	
	SockerConfig1=' Vless over TCP with XTLS , 端口:443 '
	SockerConfig2=' Trojan , 端口:443 , 连接密码:${Password} '
	SockerConfig3=' Vless over WebSocker with TLS , 端口:443 , Path : /xws '
	SockerConfig4=' Vless over TCP with TLS , 端口:443 , Path : /xltt '

	green " =================================================="
	green " PASS"
	green " =================================================="
		
}

# 添加防火墙规则
function SetFirewall(){
	green " =================================================="
	green " 添加防火墙规则..."
	green " =================================================="

	# 第一个目标端口
	if [ -n "$DestinationPort1" ]; then
		if [[ "$DestinationPort1" == "80" ]]; then
			firewall-cmd --add-service=http --permanent
		else if [[ "$DestinationPort1" == "443" ]]; then
			firewall-cmd --add-service=https --permanent
		else firewall-cmd --permanent --add-port=$DestinationPort1/tcp
		fi
		fi
	fi
	
	# 第二个目标端口
	if [ -n "$DestinationPort2" ]; then
		if [[ "$DestinationPort2" == "80" ]]; then
			firewall-cmd --add-service=http --permanent
		else if [[ "$DestinationPort2" == "443" ]]; then
			firewall-cmd --add-service=https --permanent
		else firewall-cmd --permanent --add-port=$DestinationPort2/tcp
		fi
		fi
	fi
	
	firewall-cmd --reload

	green " PASS"
}

# 安装x-ui
function InstallXUI(){

	green " =================================================="
	green " 开始安装x-ui..."
	green " =================================================="
	cd /usr/local/
	if [[ -e /usr/local/x-ui/ ]]; then
		rm -rf /usr/local/x-ui/
	fi
	wget https://github.com/sprov065/x-ui/releases/download/0.2.0/x-ui-linux-amd64.tar.gz
	tar zxvf x-ui-linux-amd64.tar.gz
	cd x-ui
	chmod +x x-ui bin/xray-linux-amd64
	cp -f x-ui.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl start x-ui
	green " 验证安装..."
	netstat -anp | grep x-ui &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" x-ui安装失败..."
		Error
    fi
	green " PASS"
	systemctl enable x-ui
	green " =================================================="
	green " 安装完成"
	green " =================================================="
}

# 端口占用检测
function PortCheck(){
	
	green " =================================================="
	green " 检测端口占用情况"
	green " =================================================="
	
	if [ -n "$DestinationPort1" ]; then
	
		PortTest1=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w $DestinationPort1`
	
	    if [ -n "$PortTest1" ]; then
			process1=`netstat -tlpn | awk -F '[: ]+' '$5=='$DestinationPort1'{print $9}'`
			ErrorInfo="检测到${DestinationPort1}端口被占用，占用进程为：${process1}，本次安装结束"
			Error
		fi
	fi
	
	if [ -n "$DestinationPort2" ]; then
	
		PortTest2=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w $DestinationPort1`
	
	    if [ -n "$PortTest2" ]; then
			process1=`netstat -tlpn | awk -F '[: ]+' '$5=='$DestinationPort2'{print $9}'`
			ErrorInfo="检测到${DestinationPort2}端口被占用，占用进程为：${process2}，本次安装结束"
			Error
		fi
	fi
	
	green " PASS"

}

# SElinux子系统检查
function SELINUXCheck(){
    osSELINUXCheck=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$osSELINUXCheck" == "SELINUX=enforcing" ]; then
        red "======================================================================="
        red "检测到SELinux为开启强制模式状态"
        red "======================================================================="
        read -p "是否允许临时设置setenforce为0 ? 请输入 [Y/n] :" osSELINUXCheckIsSetInput
        [ -z "${osSELINUXCheckIsSetInput}" ] && osSELINUXCheckIsSetInput="y"

        if [[ $osSELINUXCheckIsSetInput == [Yy] ]]; then
            # sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
        fi
    fi

    if [ "$osSELINUXCheck" == "SELINUX=permissive" ]; then
        red "======================================================================="
        red "检测到SELinux为宽容模式状态"
        red "======================================================================="
        read -p "是否允许临时设置setenforce为0 ? 请输入 [Y/n] :" osSELINUXCheckIsSetInput
        [ -z "${osSELINUXCheckIsSetInput}" ] && osSELINUXCheckIsSetInput="y"

        if [[ $osSELINUXCheckIsSetInput == [Yy] ]]; then
            # sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
        fi
    fi
}

# 安装Xray
function InstallXray(){
	
	green " =================================================="
	green " 开始安装Xray..."
	green " =================================================="
	
	green " 安装可执行文件"
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
	green " 更新 geoip.dat 和 geosite.dat 资料档"
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata
	
	green " =================================================="
	green " Xray安装完成,启动Xray..."
	green " =================================================="
	systemctl start xray
	green " 验证安装..."
	netstat -anp | grep xray &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Xray安装失败..."
		Error
    fi
	green " PASS"
	green " 将Xray加入自启动项"
	green " =================================================="
	systemctl enable xray
	green " =================================================="
	green " 安装完成!"
	green " =================================================="
	
}

# 证书自动续期预安装
function AutoCert(){
	green " =================================================="
	green " 安装EPEL扩展库..."
	green " =================================================="
	yum install -y epel-release
	green " =================================================="
	green " 安装并配置依赖环境..."
	green " =================================================="
	yum install -y snapd
	systemctl enable --now snapd.socket
	ln -s /var/lib/snapd/snap /snap
	green " =================================================="
	green " 系统将在10秒钟之后重启以应用变更..."
	green " =================================================="
	sleep 10s
	reboot
}

# 证书自动续期安装
function InstallAutoCertXray(){
	green " =================================================="
	green " 安装snap核心"
	green " =================================================="
	sleep 3s
	snap install core
	green " =================================================="
	green " 安装certbot"
	green " =================================================="
	snap install --classic certbot
	ln -s /snap/bin/certbot /usr/bin/certbot
	green " =================================================="
	green " 调整Nginx配置..."
	green " =================================================="
	systemctl stop nginx.service
	cat > "/usr/local/nginx/conf/nginx.conf" <<-EOF
worker_processes  1;
pid        /run/nginx.pid;
events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;

    keepalive_timeout  65;


    server {
        listen       80;
        listen       [::]:80;
        server_name  $Domain;

        location / {
            root   html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
EOF
	green " =================================================="
	green " 配置完成,重启服务中..."
	green " =================================================="
	systemctl start nginx.service
	green " 验证..."
	netstat -anp | grep nginx &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" Nginx启动失败...请查看日志"
		Error
    fi
	green " =================================================="
	green " PASS"
	green " =================================================="
	
	green " =================================================="
	green " 开始申请证书..."
	green " =================================================="
	certbot --nginx
	
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 证书申请失败...请查看日志"
		Error
	fi
	
	green " =================================================="
	green " 测试续订..."
	green " =================================================="
	certbot renew --dry-run
	
	# 判断执行结果
	if [ $? -ne 0 ]; then
		ErrorInfo=" 证书续订测试失败...请查看日志"
		Error
	fi
	
	green " =================================================="
	green " 证书自动化同步..."
	green " =================================================="
	systemctl stop xray
	useradd -s /usr/sbin/nologin xray
	sed -i 's/User\=nobody/User\=xray/g' /etc/systemd/system/xray.service
	systemctl daemon-reload
	systemctl start xray
	green " 配置验证..."
	netstat -anp | grep nginx &> /dev/null
	if [ $? -ne 0 ]; then
        ErrorInfo=" xray启动失败...请查看日志"
		Error
    fi
	install -d -o xray -g xray /etc/ssl/xray/
	install -m 644 -o xray -g xray /etc/letsencrypt/live/$Domain/fullchain.pem -t /etc/ssl/xray/
	install -m 600 -o xray -g xray /etc/letsencrypt/live/$Domain/privkey.pem -t /etc/ssl/xray/
	cat > "/etc/letsencrypt/renewal-hooks/deploy/xray.sh" <<-EOF
#!/bin/bash

V2RAY_DOMAIN='$Domain'

if [[ "$RENEWED_LINEAGE" == "/etc/letsencrypt/live/$V2RAY_DOMAIN" ]]; then
    install -m 644 -o xray -g xray "/etc/letsencrypt/live/$V2RAY_DOMAIN/fullchain.pem" -t /etc/ssl/xray/
    install -m 600 -o xray -g xray "/etc/letsencrypt/live/$V2RAY_DOMAIN/privkey.pem" -t /etc/ssl/xray/

    sleep "$((RANDOM % 2048))"
    systemctl restart xray.service
fi
EOF
	chmod +x /etc/letsencrypt/renewal-hooks/deploy/xray.sh
}

# 配置域名信息
function SetDomain(){
	read -p " 请输入域名(不包含协议头和斜杠) :" Domain
	green " =================================================="
	green " 您输入的域名为:"
	yellow " ${Domain}"
	green " =================================================="
	DomainYes="y"
	read -p " 确认吗? [Y/Other][默认:Y]:" DomainYes
	if [[ $DomainYes != [Yy] ]]; then
        SetDomain
    fi

}

# 设置UUID
function SetUUID(){
	UUID=$(uuidgen)
	NewUUID=$UUID
}

# 设置密码信息
function SetPassword(){
	read -p " 请输入回落点Trojan的连接密码 :" Password
	green " =================================================="
	green " 您输入的密码为:"
	yellow " ${Password}"
	green " =================================================="
	PasswordYes="y"
	read -p " 确认吗? [Y/Other][默认:Y]:" PasswordYes
	if [[ $PasswordYes != [Yy] ]]; then
        SetPassword
    fi
}

# 回显界面
function InformationDisplay(){
	green " =================================================="
	green " 请记录:"
	yellow " UUID:        ${NewUUID}"
	yellow " 配置规则:"
	if [ -n "$SockerConfig1" ]; then
		yellow "        1.    ${SockerConfig1}"
	fi
	if [ -n "$SockerConfig2" ]; then
		yellow "        2.    ${SockerConfig2}"
	fi
	if [ -n "$SockerConfig3" ]; then
		yellow "        3.    ${SockerConfig3}"
	fi
	if [ -n "$SockerConfig4" ]; then
		yellow "        4.    ${SockerConfig4}"
	fi
	green " =================================================="
	bold " 按任意键继续..."
	read
}

# 错误反馈
function Error(){
	red " =================================================="
	bold "${ErrorInfo}" 
	red " =================================================="
	sleep 6s
	exit 1
}

# 主界面
function main(){
    
	green " =================================================="
	bold  " 欢迎使用一键安装脚本"
	green " =================================================="
    green " 处理器品牌:   ${osCPU},"
	green " 处理器架构:   ${osArchitecture},"
	green " 系统信息:     ${osInfo}, ${osRelease},  "
	green " 系统版本:     ${osReleaseVersionNo}, ${osReleaseVersion},"
	green " Shell命令:    ${osSystemShell},"
	green " 包管理器:     ${osSystemPackage}"
	green " =================================================="
	yellow "    1 .安装V2ray          2 .安装Xray"
	yellow "    3 .安装x-ui           4 .编译安装Nginx"
	yellow "    5 .证书自动续期 - 预部署"
	yellow "    6 .证书自动续期 - V2ray"
	yellow "    7 .证书自动续期 - Xray"
	yellow "    8 .对接V2ray与Nginx   9 .对接Xray与Nginx"
	yellow "    q .退出"
	green " =================================================="
	read -p " 请选择功能(默认:1) [1-9.q] :" Main
    [ -z "${Main}" ] && Main="1"

    if [[ $Main == 1 ]]; then
		InstallDependentSoftware
		InstallV2ray
		main
	fi
	
	if [[ $Main == 3 ]]; then
		InstallDependentSoftware
		DestinationPort1=54321
		DestinationPort2=
		PortCheck
		InstallXUI
		SetFirewall
		main
	fi
	
	if [[ $Main == 4 ]]; then
		InstallDependentSoftware
		DestinationPort1=80
		DestinationPort2=443
		PortCheck
		InstallNginx
		SetFirewall
		main
	fi
	
	if [[ $Main == 8 ]]; then
		SetDomain
		SetUUID
		SetV2rayConfig
		InformationDisplay
		main
	fi
	
	if [[ $Main == 2 ]]; then
		InstallDependentSoftware
		InstallXray
		main
	fi
	
	if [[ $Main == 9 ]]; then
		SetDomain
		SetPassword
		SetUUID
		SetXrayConfig
		InformationDisplay
		main
	fi
	
	if [[ $Main == 5 ]]; then
		AutoCert
		exit 1
	fi
	
	if [[ $Main == 7 ]]; then
		SELINUXCheck
		SetDomain
		InstallAutoCertXray
		main
	fi
	
	if [[ $Main == q ]]; then
		green "Ok...Bye!"
		exit
	fi
	
}


ExternalEnv
main

# Natmap-portal
## 干什么

这个脚本搭配openwrt里面的Natmap使用。作用是把内网服务的最新映射地址登记到一个页面，打开就能直接点进去。
里面有一个通知脚本的功能，当IP和端口变化时通知对方，并上报到 Workers 登记成一个页面。打开页面显示服务名、地址、协议和打开按钮，不用自己手动记忆IP和端口。

## 怎么用

### 手动部署

在 GitHub 上下载好 worker.js 源码。

下载好之后打开Cloudflare.

进入后点击 Workers and Pages
![sc (1).jpeg](https://data.novaecho.org/file/1792065425235_sc__1_.jpeg)

然后点击创建应用程序
![sc (22).jpeg](https://data.novaecho.org/file/1792065420697_sc__22_.jpeg)

从Hello World开始
![sc (21).jpeg](https://data.novaecho.org/file/1792065422356_sc__21_.jpeg)

起个名字，名字随便起
![sc (20).jpeg](https://data.novaecho.org/file/1792065426596_sc__20_.jpeg)

编辑代码
![sc (19).jpeg](https://data.novaecho.org/file/1792065421581_sc__19_.jpeg)

将刚才下载下来的worker.js源码粘贴上去
![sc (18).jpeg](https://data.novaecho.org/file/1792065418438_sc__18_.jpeg)

创建好之后，来到存储和数据库，点击KV命名空间
![sc (17).jpeg](https://data.novaecho.org/file/1792065412276_sc__17_.jpeg)

创建KV空间
![sc (16).jpeg](https://data.novaecho.org/file/1792065412448_sc__16_.jpeg)

自己起个名字
![sc (15).jpeg](https://data.novaecho.org/file/1792065412088_sc__15_.jpeg)

完成后重新回到 Workers and Pages，找到刚才创建的项目，点击设置，找到绑定
![sc (14).jpeg](https://data.novaecho.org/file/1792065411323_sc__14_.jpeg)

绑定KV空间
![sc (13).jpeg](https://data.novaecho.org/file/1792065418249_sc__13_.jpeg)

添加绑定，变量名为大写的KV
![屏幕截图 2026-10-15 192755.png](https://data.novaecho.org/file/1792065751815_屏幕截图_2026-10-15_192755.png)

添加相关变量，变量名稍后下文会提到。根据你的需求按需添加即可。
![sc (12).jpeg](https://data.novaecho.org/file/1792065413039_sc__12_.jpeg)

必填

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ADMIN_PASSWORD` | — | 管理页密码。**留空或未设 = 管理禁用(403)**&#8203;，无法创建任何服务 |

建议填

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | 管理页用户名，与 `ADMIN_PASSWORD` 配套使用 |
| `INDEX_PASSWORD` | 空 | 目录页密码。**留空 = 目录页免密**，任何拿到链接的人都能看到所有内网服务名和地址 |
| `SESSION_SECRET` | — | 会话签名密钥。不设则由四个密码派生，建议用 `openssl rand -hex 32` 生成 |
| `INDEX_PATH` | `user` | 目录页路径。**建议改成随机串**，默认值容易被扫描器猜到 |
| `ADMIN_PATH` | `admin` | 管理页路径。**同上**。与 `INDEX_PATH` 不能相同，否则返回 500 |

可选

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `INDEX_USERNAME` | `user` | 目录页用户名 |
| `MAX_LOGIN_ATTEMPTS` | `5` | 同 IP 连续失败多少次锁定，有效范围 1–100，超出被静默钳制 |
| `LOCKOUT_SECONDS` | `300` | 锁定时长（秒），有效范围 10–86400，超出被静默钳制 |
| `PUBLIC_DOMAIN` | 空 | 公网域名，填了就用它替代上报的 IP 生成链接。支持带 `https://` 前缀和结尾斜杠；非法值会被忽略并回退为上报 IP |
| `TIMEZONE` | `Asia/Shanghai` | 页面时间显示时区。非法值静默回退默认，不报错 |
| `REPORT_RATE_LIMIT` | `30` | 每 IP 每 10 秒最多上报次数，有效范围 0–10000。`0` 表示关闭限流 |

密码类变量请用 secret 类型设置，而不是普通的变量。

注意事项

- 取值超出有效范围**不会报错**，会被静默钳制到边界值。填错时行为与预期不符但不提示。
- `INDEX_PATH` 与 `ADMIN_PATH` 设置为相同值时，服务启动即返回 500。
- `ADMIN_PASSWORD` 未设时管理页返回 403，属于功能禁用而非降级到弱保护。
- `INDEX_PASSWORD` 未设时目录页完全公开，页面上会列出所有服务名与地址。

### 继续

来到“域”这一选项卡，自己绑定一个域名。workers.dev 域名在国内被墙了，建议绑定一个自己的域名。关于如何获取域名以及托管到 Cloudflare 上面，请自行上网搜索。
![sc (11).jpeg](https://data.novaecho.org/file/1792065938283_sc__11_.jpeg)

![sc (10).jpeg](https://data.novaecho.org/file/1792065414824_sc__10_.jpeg)

### 创建服务

创建好之后，点击右上角的访问，尝试直接访问
![sc (9).jpeg](https://data.novaecho.org/file/1792065414402_sc__9_.jpeg)

如果你配置了 IndexPath 变量的话，默认应该返回 404 页面。

在路径后面添加上你当时配置的INDEX_PATH变量，然后访问，应该会跳出用户认证页面
![屏幕截图 2026-10-15 193435.png](https://data.novaecho.org/file/1792066304184_屏幕截图_2026-10-15_193435.png)

输入你当时配置的那些变量名，然后应该进入了一个首页，点击下面的管理页

然后再输一遍你配置的管理员密码

然后进到这个页面 
![sc (7).jpeg](https://data.novaecho.org/file/1792065412189_sc__7_.jpeg)

自己给你的服务起一个名字，然后点击“创建密钥”

密钥创建出来之后，只显示这一次，尽快保存
![sc (6).jpeg](https://data.novaecho.org/file/1792065409473_sc__6_.jpeg)

通过.sh脚本调用

登录到OpenWRT的SSH，新建一个点SH脚本，路径自己选，名字也自己选，能记住就行

vi /root/natmap.sh

使用VI或nano编辑器（如果已安装）创建文件，文件内容如下：

```sh
#!/bin/sh
SERVER="https://"
TOKEN=""

IP="${1}"
PORT="${2}"
PROTO="$(echo "${5:-tcp}" | tr 'A-Z' 'a-z')"

if [ -z "$IP" ] || [ -z "$PORT" ]; then
	logger -t natmap-report "参数不全 ip='$IP' port='$PORT'，跳过"
	exit 1
fi

RESP=$(uclient-fetch -q -O - --timeout=10 \
	--header='Content-Type: application/json' \
	--post-data="{\"token\":\"$TOKEN\",\"ip\":\"$IP\",\"port\":$PORT,\"protocol\":\"$PROTO\"}" \
	"$SERVER/api/report" 2>&1)
RC=$?

if [ $RC -ne 0 ]; then
	logger -t natmap-report "请求失败 rc=$RC，原始输出：${RESP:-空}"
	exit 1
fi

case "$RESP" in
	*'"ok":true'*)
		logger -t natmap-report "$IP:$PORT/$PROTO 上报成功"
		;;
	*)
		logger -t natmap-report "服务端拒绝: ${RESP:-空}"
		exit 1
		;;
esac
```

然后根据实际，修改顶部两行：

```sh
SERVER="https://你的workers域名"
TOKEN="管理页生成的那串token"
```

然后在 natmap 的 **通知脚本** 里填 `/root/natmap.sh`，并加上执行权限：

```sh
chmod +x /root/natmap.sh
```

![sc (5).jpeg](https://data.novaecho.org/file/1792065407788_sc__5_.jpeg)

![sc (4).jpeg](https://data.novaecho.org/file/1792065410830_sc__4_.jpeg)

natmap 每次打洞成功后会自动调用它上报。验证：

![sc (3).jpeg](https://data.novaecho.org/file/1792065405511_sc__3_.jpeg)

日志能看到 `上报成功` 就通了。

<details>
<summary>非 OpenWrt 环境</summary>

任何能发 HTTP POST 的环境都行，比如每 5 分钟跑一次：

```bash
curl -X POST https://你的域名/api/report \
  -H 'Content-Type: application/json' \
  -d '{"token":"TOKEN","ip":"192.168.1.5","port":8080,"protocol":"tcp"}'
```

</details>

### 上报接口

`POST /api/report`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `token` | string | 是 | 创建服务时生成的那串密钥 |
| `ip` | string | 是 | IPv4、IPv6 或主机名 |
| `port` | number | 是 | 0–65535，`0` 表示默认端口 |
| `protocol` | string | 否 | `tcp`（默认）或 `udp` |

## 部署建议

1. **务必设置 `ADMIN_PASSWORD`**，留空等于管理功能禁用
2. **建议设置 `SESSION_SECRET`**，用 `openssl rand -hex 32` 生成
3. 把 `INDEX_PATH` / `ADMIN_PATH` 改成随机串，默认值容易被扫描器猜到
4. `INDEX_PASSWORD` 留空 = 目录页完全公开，任何拿到链接的人都能看到你所有内网服务名和地址

**目前只是一个雏形，做的还不太好，只保证基本能用，有问题到时候我会改，也可以提issue.**

**需要注意，即使你的访问地址、后台路径和密码设得复杂，但不排除您的IP和端口有可能会被黑客发现的行为，我们不对此做出任何保证。使用本软件时请自行对安全性负责，使用本软件造成的任何后果均由用户本人承担，与作者无关。下载和使用此代码即代表您已同意此条款。**

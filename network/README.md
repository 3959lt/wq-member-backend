# 自动节点（0.3.0）

当前使用 Xray v26.3.27，VMess AEAD / TCP，监听 443。每位普通用户分配一个 UUID，用户配置由后台自动生成，支持 Mihomo。客户端配置 `tls: false`，VMess 自身提供加密；该端口不是网页 HTTPS 服务。

## 操作

1. 管理员打开“网络服务”，给需要测试的普通用户人工开通天数。
2. 等待约 15–30 秒，查看节点同步状态。
3. 普通用户登录“会员中心”，生成订阅链接，导入 Mihomo / Clash Verge Rev 并选择自动节点。
4. 在客户端启用系统代理；如果要覆盖更多应用流量，需要客户端自行启用 TUN 模式。
5. 停用账号、撤销节点授权、到期、停止订阅、下架自动节点或耗尽累计额度，都会在下一次节点同步时撤销实际授权。
6. 重置“订阅链接”只撤销旧链接；重置“节点凭证”会更换 UUID，并撤销旧凭证。用户必须刷新订阅。

## 用量和限制

上行＋下行计入累计用量。额度单位为 GiB，0 表示不限制；续期不会自动清零。约 15 秒采集一次，超过额度到节点撤销之间有短暂延迟。节点异常退出可能丢失最后一个采集周期的数据，不能直接用作精确计费或 AWS 流量对账。

首版同步通过更新配置并重启节点实现，因此授权变化会断开该节点的现有连接，客户端需重连。支持用户独立凭证，但没有严格的设备数、连接数或每用户限速。

节点阻止访问环回、私网、链路本地与 AWS 实例元数据等地址。只启用本机 StatsService API（127.0.0.1:10085），不对公网暴露控制接口。同步失败时停止节点，防止继续使用过期授权；统计暂时失败时仍继续处理授权。

## 运维

```sh
sudo systemctl status wq-xray wq-node-sync.timer
sudo systemctl start wq-node-sync
sudo journalctl -u wq-node-sync -n 30 --no-pager
```

节点配置位于 /etc/wq-xray/config.json，包含 UUID，不可提交 Git。同步程序运行于 wqbackend，只有对 wq-xray 服务执行 restart/stop 的有限 sudo 权限。

## 部署依赖

服务示例要求已安装 /usr/local/lib/wq-xray/xray；Xray 发行包应从官方项目下载并核验摘要。后台与同步脚本共用 /var/lib/wq-backend/app.sqlite3。需要 root 安装 systemd 单元、建立 wqxray 账号和 /etc/wq-xray 目录，并设置适当文件权限。数据库 net_settings 的公开地址应是实际服务器地址，port 必须为 443，与同步脚本固定监听端口一致。

正式服务还需要安全的后台与订阅 HTTPS 入口、负载测试、告警和更精确的计费采集；当前后台 HTTP 不加密凭证传输。

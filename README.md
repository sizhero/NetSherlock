## 文件说明

| 文件 | 说明 | 特征数 |
|---|---|---|
| `network_flow_features_single_flow.csv` | 单条流可提取的特征 | 675 |
| `network_flow_features_description.csv` | 总表（single + multi） | 697 |

## single_flow.csv 新增特征说明

相比初始版本（472 个特征），新增了 **203 个特征**（整合后去除了语义重复），来源如下：

### DOCX1/DOCX2 — 75 个

- **行号范围**：第 474 行 ~ 第 548 行
- **涉及分类**：统计特征、TLS特征、HTTP特征、DNS特征、域名特征、协议头部特征、行为特征、序列特征
- **主要内容**：包长分位数与熵、突发特征、TLS 握手与证书特征、JA3/JA3S 指纹、HTTP 头部特征、DNS 查询统计、域名字符统计等

### DOCX3 — 128 个

- **行号范围**：第 549 行 ~ 第 676 行
- **涉及分类**：统计特征、TLS特征、HTTP特征、协议头部特征、SSH特征、NTP特征、QUIC特征、MQTT特征、DNS特征、RTP特征、FTP特征、IRC特征、SIP特征、RTCP特征、SDP特征、ICMP特征
- **主要内容**：各协议的细粒度字段级特征（SSL/TLS 证书详细信息、HTTP 请求字段、TCP 序列号统计、SSH/NTP/QUIC/MQTT/DNS/RTP/FTP/IRC/SIP/RTCP/SDP/ICMP 协议特征）

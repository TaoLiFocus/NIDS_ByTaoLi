# 基于Suricata的网络入侵检测系统

这是一个基于Suricata的网络入侵检测系统(NIDS)，包括前后端完整实现。系统可以实时监控网络流量，分析PCAP文件，并提供可视化的告警管理界面。

## 功能特点

- **用户认证**: 支持用户注册、登录和密码重置，完善的用户权限管理
- **实时监控**: 通过Suricata实时监控网络流量并检测入侵行为
- **数据可视化**: 直观的仪表盘展示安全态势，支持多种图表类型
- **告警管理**: 集中展示和管理告警信息，支持按严重程度和类型分类
- **PCAP分析**: 上传并分析PCAP文件，查看详细告警信息
- **规则管理**: 添加、编辑和删除Suricata规则，支持规则状态切换
- **系统设置**: 修改密码等个性化配置

## 技术栈

### 后端

- **Flask**: Web框架，提供RESTful API
- **SQLAlchemy**: ORM库，数据库交互
- **JWT**: 用于用户身份验证和授权
- **bcrypt**: 密码安全哈希和验证
- **MySQL**: 关系型数据库存储
- **Suricata**: 核心入侵检测引擎

### 前端

- **React**: 前端UI框架
- **TypeScript**: 类型安全的JavaScript超集
- **Ant Design**: UI组件库，提供美观的用户界面
- **Charts**: 使用@ant-design/charts实现数据可视化
- **Axios**: HTTP请求处理
- **React Router**: 前端路由管理

## 系统架构

系统由三个主要部分组成：

1. **Suricata引擎**: 负责网络流量捕获和入侵检测
2. **后端服务**: Flask应用，处理API请求，与数据库和Suricata交互
3. **前端应用**: React应用，提供用户界面

## 安装与部署

### 系统要求

- **操作系统**: Linux (推荐Ubuntu 20.04+)
- **Python**: 3.8+
- **Node.js**: 14+
- **MySQL**: 5.7+
- **Suricata**: 6.0+

### 自动安装

使用提供的安装脚本进行快速部署：

```bash
# 克隆仓库
git clone https://github.com/yourusername/NIDS_ByTaoLi.git
cd NIDS_ByTaoLi

# 运行安装脚本
chmod +x install.sh
./install.sh
```

安装脚本会自动：
- 检查系统依赖
- 创建必要的目录
- 安装Python和Node.js依赖
- 配置数据库
- 设置Suricata

### 手动安装

#### 1. 安装系统依赖

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev mysql-server libmysqlclient-dev suricata nodejs npm
```

#### 2. 配置后端

```bash
# 安装Python依赖
cd backend
pip3 install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑.env文件设置数据库连接等

# 初始化数据库
python3 reset_db.py
```

#### 3. 配置前端

```bash
cd frontend
npm install
```

#### 4. 配置Suricata

```bash
# 确保Suricata规则和日志目录有正确权限
sudo chmod -R 755 /etc/suricata/rules
sudo chmod -R 755 /var/log/suricata
```

## 使用指南

### 启动系统

使用提供的启动脚本启动所有服务：

```bash
./start.sh
```

启动后:
- 后端服务运行在: http://localhost:5000/
- 前端界面访问: http://localhost:3000/

### 停止系统

使用提供的停止脚本停止所有服务：

```bash
./stop.sh
```

### 使用流程

1. 访问http://localhost:3000登录系统
   - 默认管理员账户: admin/admin123

2. 系统功能导航:
   - **仪表盘**: 查看总体安全态势
   - **实时监控**: 启动/停止流量监控，查看实时告警
   - **PCAP分析**: 上传PCAP文件进行分析
   - **系统设置**: 管理规则和个人信息

3. 安全建议:
   - 首次登录后请修改默认密码
   - 修改密码后系统会自动登出，需要重新登录

## 常见问题排查

1. **数据库连接问题**:
   - 检查MySQL服务是否运行: `sudo systemctl status mysql`
   - 确认.env文件中的数据库连接信息正确

2. **Suricata启动失败**:
   - 检查Suricata配置: `sudo suricata -T -c /etc/suricata/suricata.yaml`
   - 确认网络接口名称正确: `ip addr show`

3. **前端登录问题**:
   - 查看浏览器控制台错误信息
   - 确认后端服务正常运行

## 贡献指南

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

MIT License 
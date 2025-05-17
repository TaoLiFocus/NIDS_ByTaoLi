# NIDS系统API文档

本文档详细记录了基于Suricata的网络入侵检测系统(NIDS)的前后端API接口定义。

## 基础URL

所有API调用基于以下基础URL:
```
http://localhost:5000/api
```

## 认证机制

除了登录和注册接口外，所有API请求都需要在HTTP请求头中包含JWT令牌进行认证:
```
Authorization: Bearer <access_token>
```

## 用户认证API

### 1. 用户登录

**描述**: 用户登录并获取访问令牌

**请求**:
- 方法: `POST`
- URL: `/auth/login`
- Content-Type: `application/json`
- 参数:

```json
{
  "username": "用户名",
  "password": "密码"
}
```

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "登录成功",
  "access_token": "jwt访问令牌",
  "refresh_token": "jwt刷新令牌",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2025-05-17T11:08:11",
    "updated_at": "2025-05-17T11:08:11"
  }
}
```

### 2. 用户注册

**描述**: 注册新用户

**请求**:
- 方法: `POST`
- URL: `/auth/register`
- Content-Type: `application/json`
- 参数:

```json
{
  "username": "新用户名",
  "email": "user@example.com",
  "password": "密码"
}
```

**响应**:
- 状态码: 201
- 内容:

```json
{
  "message": "注册成功",
  "user": {
    "id": 2,
    "username": "newuser",
    "email": "user@example.com",
    "role": "user",
    "is_active": true,
    "created_at": "2025-05-17T13:24:59",
    "updated_at": "2025-05-17T13:24:59"
  }
}
```

### 3. 获取用户资料

**描述**: 获取当前登录用户的详细信息

**请求**:
- 方法: `GET`
- URL: `/auth/profile`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2025-05-17T11:08:11",
    "updated_at": "2025-05-17T11:08:11"
  }
}
```

### 4. 修改密码

**描述**: 修改当前登录用户的密码

**请求**:
- 方法: `POST`
- URL: `/auth/change-password`
- Content-Type: `application/json`
- 请求头: `Authorization: Bearer <access_token>`
- 参数:

```json
{
  "old_password": "当前密码",
  "new_password": "新密码"
}
```

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "密码修改成功"
}
```

## 监控API

### 1. 获取告警列表

**描述**: 获取系统检测到的告警列表

**请求**:
- 方法: `GET`
- URL: `/monitor/alerts`
- 请求头: `Authorization: Bearer <access_token>`
- 查询参数:
  - `page`: 页码，默认为1
  - `per_page`: 每页项数，默认为20

**响应**:
- 状态码: 200
- 内容:

```json
{
  "alerts": [
    {
      "id": 1,
      "timestamp": "2025-05-17T10:23:45",
      "alert_action": "allowed",
      "alert_signature_id": 2034567,
      "alert_signature": "ET POLICY SSH Outbound Connection",
      "alert_category": "Potentially Bad Traffic",
      "alert_severity": 2,
      "src_ip": "192.168.1.5",
      "dest_ip": "198.51.100.123",
      "src_port": 54321,
      "dest_port": 22,
      "proto": "TCP",
      "app_proto": "ssh",
      "pcap_filename": null
    }
    // 更多告警...
  ],
  "total": 150,
  "pages": 8,
  "page": 1,
  "per_page": 20
}
```

### 2. 获取告警统计

**描述**: 获取系统告警统计信息

**请求**:
- 方法: `GET`
- URL: `/monitor/alerts/summary`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "total_alerts": 150,
  "severity_stats": {
    "1": 45,
    "2": 68,
    "3": 37
  },
  "category_stats": {
    "Potentially Bad Traffic": 42,
    "Attempted Information Leak": 28,
    "Web Application Attack": 35,
    "Trojan Activity": 15,
    "Other": 30
  },
  "src_ip_stats": {
    "192.168.1.5": 25,
    "192.168.1.10": 18,
    "192.168.1.15": 12
    // 更多IP统计...
  }
}
```

### 3. 启动监控

**描述**: 启动Suricata监控服务

**请求**:
- 方法: `POST`
- URL: `/monitor/start`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "监控服务已启动"
}
```

### 4. 停止监控

**描述**: 停止Suricata监控服务

**请求**:
- 方法: `POST`
- URL: `/monitor/stop`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "监控服务已停止"
}
```

### 5. 获取监控状态

**描述**: 获取当前Suricata监控服务状态

**请求**:
- 方法: `GET`
- URL: `/monitor/status`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "is_running": true
}
```

## PCAP分析API

### 1. 上传PCAP文件

**描述**: 上传PCAP文件进行分析

**请求**:
- 方法: `POST`
- URL: `/pcap/upload`
- 请求头: `Authorization: Bearer <access_token>`
- Content-Type: `multipart/form-data`
- 参数:
  - `file`: PCAP文件数据

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "文件上传成功",
  "pcap_id": 12,
  "filename": "capture_2025_05_17.pcap",
  "status": "pending"
}
```

### 2. 获取PCAP文件列表

**描述**: 获取所有上传的PCAP文件列表

**请求**:
- 方法: `GET`
- URL: `/pcap/files`
- 请求头: `Authorization: Bearer <access_token>`
- 查询参数:
  - `page`: 页码，默认为1
  - `per_page`: 每页项数，默认为10

**响应**:
- 状态码: 200
- 内容:

```json
{
  "pcap_files": [
    {
      "id": 12,
      "filename": "capture_2025_05_17.pcap",
      "file_path": "/uploads/capture_2025_05_17.pcap",
      "file_size": 1507328,
      "upload_time": "2025-05-17T14:35:22",
      "status": "completed",
      "user_id": 1
    }
    // 更多文件...
  ],
  "total": 25,
  "pages": 3,
  "page": 1,
  "per_page": 10
}
```

### 3. 获取PCAP文件分析结果

**描述**: 获取指定PCAP文件的分析结果

**请求**:
- 方法: `GET`
- URL: `/pcap/files/{pcap_id}/analysis`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "pcap_id": 12,
  "filename": "capture_2025_05_17.pcap",
  "status": "completed",
  "alerts": [
    {
      "id": 235,
      "timestamp": "2025-05-17T10:23:45",
      "alert_signature": "ET POLICY SSH Outbound Connection",
      "alert_category": "Potentially Bad Traffic",
      "alert_severity": 2,
      "src_ip": "192.168.1.5",
      "dest_ip": "198.51.100.123",
      "src_port": 54321,
      "dest_port": 22,
      "proto": "TCP",
      "app_proto": "ssh"
    }
    // 更多告警...
  ],
  "statistics": {
    "total_packets": 12532,
    "total_bytes": 1507328,
    "protocols": {
      "TCP": 8743,
      "UDP": 3456,
      "ICMP": 321,
      "Other": 12
    },
    "total_alerts": 37
  }
}
```

## 系统设置API

### 1. 获取规则列表

**描述**: 获取所有Suricata规则

**请求**:
- 方法: `GET`
- URL: `/settings/rules`
- 请求头: `Authorization: Bearer <access_token>`
- 查询参数:
  - `page`: 页码，默认为1
  - `per_page`: 每页项数，默认为10

**响应**:
- 状态码: 200
- 内容:

```json
{
  "rules": [
    {
      "id": 1,
      "name": "SSH检测规则",
      "content": "alert tcp any any -> any 22 (msg:\"ET POLICY SSH Outbound Connection\"; flow:established,to_server; dsize:<100; classtype:policy-violation; sid:2018358; rev:3;)",
      "description": "检测SSH出站连接",
      "is_enabled": true,
      "created_at": "2025-05-17T09:42:15",
      "updated_at": "2025-05-17T09:42:15"
    }
    // 更多规则...
  ],
  "total": 45,
  "pages": 5,
  "page": 1,
  "per_page": 10
}
```

### 2. 创建规则

**描述**: 创建新的Suricata规则

**请求**:
- 方法: `POST`
- URL: `/settings/rules`
- 请求头: `Authorization: Bearer <access_token>`
- Content-Type: `application/json`
- 参数:

```json
{
  "name": "HTTP检测规则",
  "content": "alert http any any -> any any (msg:\"HTTP XSS攻击尝试\"; content:\"<script>\"; http_uri; nocase; sid:1000001; rev:1;)",
  "description": "检测HTTP XSS攻击",
  "is_enabled": true
}
```

**响应**:
- 状态码: 201
- 内容:

```json
{
  "message": "规则创建成功",
  "rule": {
    "id": 46,
    "name": "HTTP检测规则",
    "content": "alert http any any -> any any (msg:\"HTTP XSS攻击尝试\"; content:\"<script>\"; http_uri; nocase; sid:1000001; rev:1;)",
    "description": "检测HTTP XSS攻击",
    "is_enabled": true,
    "created_at": "2025-05-17T15:10:22",
    "updated_at": "2025-05-17T15:10:22"
  }
}
```

### 3. 更新规则

**描述**: 更新现有Suricata规则

**请求**:
- 方法: `PUT`
- URL: `/settings/rules/{rule_id}`
- 请求头: `Authorization: Bearer <access_token>`
- Content-Type: `application/json`
- 参数:

```json
{
  "name": "HTTP检测规则（更新）",
  "content": "alert http any any -> any any (msg:\"HTTP XSS攻击尝试\"; content:\"<script>\"; http_uri; nocase; sid:1000001; rev:2;)",
  "description": "检测HTTP XSS攻击（更新版本）",
  "is_enabled": true
}
```

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "规则更新成功",
  "rule": {
    "id": 46,
    "name": "HTTP检测规则（更新）",
    "content": "alert http any any -> any any (msg:\"HTTP XSS攻击尝试\"; content:\"<script>\"; http_uri; nocase; sid:1000001; rev:2;)",
    "description": "检测HTTP XSS攻击（更新版本）",
    "is_enabled": true,
    "created_at": "2025-05-17T15:10:22",
    "updated_at": "2025-05-17T15:25:48"
  }
}
```

### 4. 删除规则

**描述**: 删除Suricata规则

**请求**:
- 方法: `DELETE`
- URL: `/settings/rules/{rule_id}`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "规则删除成功"
}
```

### 5. 重启Suricata服务

**描述**: 重启Suricata服务以应用规则变更

**请求**:
- 方法: `POST`
- URL: `/settings/restart-suricata`
- 请求头: `Authorization: Bearer <access_token>`

**响应**:
- 状态码: 200
- 内容:

```json
{
  "message": "Suricata服务已重启"
}
```

## 错误响应

所有API在遇到错误时将返回以下格式的响应：

**未授权访问**:
- 状态码: 401
- 内容:
```json
{
  "message": "未授权访问"
}
```

**无权限**:
- 状态码: 403
- 内容:
```json
{
  "message": "无权限进行此操作"
}
```

**资源不存在**:
- 状态码: 404
- 内容:
```json
{
  "message": "请求的资源不存在"
}
```

**服务器错误**:
- 状态码: 500
- 内容:
```json
{
  "message": "服务器内部错误"
}
``` 
#!/bin/bash

# 显示彩色输出
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # 无颜色

# 打印带颜色的信息
print_info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 未安装，请先安装此依赖"
        return 1
    fi
    return 0
}

# 创建目录
create_directories() {
    print_info "创建必要目录..."
    
    # 创建上传目录
    mkdir -p backend/uploads
    mkdir -p backend/logs
    
    # 确保Suricata规则目录存在
    sudo mkdir -p /etc/suricata/rules
    sudo chmod 755 /etc/suricata/rules
}

# 检查系统依赖
check_dependencies() {
    print_info "检查系统依赖..."
    
    local missing_deps=0
    
    # 检查Python
    if check_command python3; then
        python_version=$(python3 --version)
        print_info "检测到 $python_version"
    else
        print_error "未检测到Python3，请安装Python 3.7+"
        missing_deps=1
    fi
    
    # 检查pip
    if check_command pip3; then
        pip_version=$(pip3 --version)
        print_info "检测到 pip $(echo $pip_version | awk '{print $2}')"
    else
        print_error "未检测到pip3，请安装pip"
        missing_deps=1
    fi
    
    # 检查Node.js
    if check_command node; then
        node_version=$(node --version)
        print_info "检测到 Node.js $node_version"
    else
        print_error "未检测到Node.js，请安装Node.js 14+"
        missing_deps=1
    fi
    
    # 检查npm
    if check_command npm; then
        npm_version=$(npm --version)
        print_info "检测到 npm $npm_version"
    else
        print_error "未检测到npm，请安装npm"
        missing_deps=1
    fi
    
    # 检查MySQL
    if check_command mysql; then
        mysql_version=$(mysql --version)
        print_info "检测到 $(echo $mysql_version | awk '{print $1" "$2" "$3" "$5}')"
    else
        print_error "未检测到MySQL，请安装MySQL 5.7+"
        missing_deps=1
    fi
    
    # 检查Suricata
    if check_command suricata; then
        suricata_version=$(suricata --build-info | grep "Version" | awk '{print $2}')
        print_info "检测到 Suricata $suricata_version"
    else
        print_error "未检测到Suricata，请安装Suricata 6.0+"
        missing_deps=1
    fi
    
    if [ $missing_deps -eq 1 ]; then
        print_error "安装系统依赖失败。请先安装缺少的依赖，然后重新运行此脚本。"
        print_info "可以使用以下命令安装所需依赖:"
        echo "sudo apt-get update"
        echo "sudo apt-get install -y python3 python3-pip python3-dev mysql-server libmysqlclient-dev suricata nodejs npm"
        exit 1
    fi
}

# 安装Python依赖
install_python_deps() {
    print_info "安装Python依赖..."
    pip3 install -r backend/requirements.txt
    
    if [ $? -ne 0 ]; then
        print_error "安装Python依赖失败"
        exit 1
    fi
    
    print_info "Python依赖安装完成"
}

# 安装Node.js依赖
install_node_deps() {
    print_info "安装Node.js依赖..."
    cd frontend && npm install
    
    if [ $? -ne 0 ]; then
        print_error "安装Node.js依赖失败"
        exit 1
    fi
    
    print_info "Node.js依赖安装完成"
    cd ..
}

# 配置MySQL数据库
configure_database() {
    print_info "配置MySQL数据库..."
    
    read -p "请输入MySQL用户名 [root]: " mysql_user
    mysql_user=${mysql_user:-root}
    
    read -sp "请输入MySQL密码: " mysql_password
    echo ""
    
    if [ -z "$mysql_password" ]; then
        print_warn "未提供密码，尝试无密码连接MySQL"
    fi
    
    # 测试数据库连接
    if [ -z "$mysql_password" ]; then
        mysql -u $mysql_user -e "SELECT 1" > /dev/null 2>&1
    else
        mysql -u $mysql_user -p"$mysql_password" -e "SELECT 1" > /dev/null 2>&1
    fi
    
    if [ $? -ne 0 ]; then
        print_error "数据库连接失败，请检查用户名和密码"
        exit 1
    fi
    
    # 创建数据库
    print_info "创建数据库 nids_db..."
    
    if [ -z "$mysql_password" ]; then
        mysql -u $mysql_user -e "CREATE DATABASE IF NOT EXISTS nids_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    else
        mysql -u $mysql_user -p"$mysql_password" -e "CREATE DATABASE IF NOT EXISTS nids_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    fi
    
    if [ $? -ne 0 ]; then
        print_error "创建数据库失败"
        exit 1
    fi
    
    print_info "数据库配置完成"
    
    # 创建环境变量配置文件
    print_info "创建环境变量配置文件..."
    
    cat > backend/.env << EOF
# Flask配置
SECRET_KEY=$(openssl rand -hex 16)
FLASK_DEBUG=true
FLASK_CONFIG=default

# 数据库配置
DATABASE_URL=mysql+pymysql://$mysql_user:$mysql_password@localhost/nids_db

# JWT配置
JWT_SECRET_KEY=$(openssl rand -hex 16)

# Suricata配置
SURICATA_BIN=/usr/bin/suricata
SURICATA_RULES_DIR=/etc/suricata/rules
SURICATA_CONFIG=/etc/suricata/suricata.yaml
SURICATA_LOG_DIR=/var/log/suricata
SURICATA_EVE_JSON=/var/log/suricata/eve.json

# 网络接口
INTERFACE=ens33
EOF
    
    print_info "环境变量配置文件创建完成"
}

# 配置Suricata
configure_suricata() {
    print_info "配置Suricata..."
    
    # 设置Suricata规则权限
    if [ -d "/etc/suricata/rules" ]; then
        sudo chmod -R 755 /etc/suricata/rules
        sudo chown -R $(whoami):$(whoami) /etc/suricata/rules 2>/dev/null || true
    fi
    
    # 设置Suricata日志权限
    if [ -d "/var/log/suricata" ]; then
        sudo chmod -R 755 /var/log/suricata
        sudo chown -R $(whoami):$(whoami) /var/log/suricata 2>/dev/null || true
    fi
    
    print_info "Suricata配置完成"
}

# 检查实际网络接口名称
check_network_interface() {
    print_info "检查实际网络接口名称..."
    ip addr show | grep -E '^[0-9]'
}

# 检查Suricata配置
check_suricata_config() {
    print_info "检查Suricata配置..."
    sudo suricata -T -c /etc/suricata/suricata.yaml
}

# 使用更多调试信息启动Suricata
start_suricata_debug() {
    print_info "使用更多调试信息启动Suricata..."
    sudo suricata -c /etc/suricata/suricata.yaml -i $(ip -o -4 route show to default | awk '{print $5}') -v
}

# 主函数
main() {
    print_info "开始安装基于Suricata的网络入侵检测系统..."
    
    # 检查是否以root用户运行
    if [ "$EUID" -eq 0 ]; then
        print_warn "请不要以root用户运行此脚本，使用普通用户并在需要时使用sudo"
        exit 1
    fi
    
    check_dependencies
    create_directories
    install_python_deps
    install_node_deps
    configure_database
    configure_suricata
    check_network_interface
    check_suricata_config
    start_suricata_debug
    
    print_info "安装完成！"
    print_info "使用以下命令启动服务:"
    print_info "  ./start.sh"
    print_info "使用以下命令停止服务:"
    print_info "  ./stop.sh"
}

# 执行主函数
main 
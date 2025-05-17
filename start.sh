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

# 检查目录和文件
check_requirements() {
    print_info "检查系统环境..."
    
    # 检查后端目录
    if [ ! -d "backend" ]; then
        print_error "未找到backend目录，请确保在正确的项目根目录下运行此脚本"
        exit 1
    fi
    
    # 检查前端目录
    if [ ! -d "frontend" ]; then
        print_error "未找到frontend目录，请确保在正确的项目根目录下运行此脚本"
        exit 1
    fi
    
    # 检查环境变量文件
    if [ ! -f "backend/.env" ]; then
        print_error "未找到环境变量配置文件，请先运行install.sh脚本"
        exit 1
    fi
}

# 确保PID目录存在
ensure_pid_dir() {
    if [ ! -d "backend/pids" ]; then
        mkdir -p backend/pids
    fi
}

# 启动Suricata
start_suricata() {
    print_info "启动Suricata..."
    
    # 获取配置的网络接口
    INTERFACE=$(grep "INTERFACE=" backend/.env | cut -d '=' -f2)
    
    # 检查是否已启动
    if pidof -x suricata >/dev/null; then
        print_warn "Suricata已经在运行，跳过启动"
        return
    fi
    
    # 检查并删除过时的PID文件
    if [ -f "/var/run/suricata.pid" ]; then
        print_warn "发现过时的Suricata PID文件，尝试删除..."
        sudo rm -f /var/run/suricata.pid
    fi
    
    # 确保Suricata日志目录存在且有正确权限
    if [ ! -d "/var/log/suricata" ]; then
        print_info "创建Suricata日志目录..."
        sudo mkdir -p /var/log/suricata
    fi
    sudo chmod 755 /var/log/suricata
    sudo chown -R $(whoami):$(whoami) /var/log/suricata 2>/dev/null || true
    
    # 尝试启动Suricata
    print_info "使用接口 ${INTERFACE:-ens33} 启动Suricata..."
    sudo suricata -c /etc/suricata/suricata.yaml -i ${INTERFACE:-ens33} -D
    
    # 等待片刻让服务启动
    sleep 2
    
    # 检查是否启动成功
    if pidof -x suricata >/dev/null; then
        print_info "Suricata启动成功"
    else
        print_error "Suricata启动失败"
        print_info "尝试检查Suricata配置文件是否有错误..."
        sudo suricata -T -c /etc/suricata/suricata.yaml
        print_error "请修复配置文件问题后再尝试启动"
        exit 1
    fi
}

# 启动后端服务
start_backend() {
    print_info "启动后端服务..."
    
    # 检查是否已经在运行
    if [ -f "backend/server.pid" ]; then
        PID=$(cat backend/server.pid)
        if ps -p $PID > /dev/null; then
            print_warn "后端服务已经在运行 (PID: $PID)"
            return
        else
            # 进程不存在但PID文件存在，删除PID文件
            rm backend/server.pid
        fi
    fi
    
    # 进入后端目录
    cd backend
    
    # 启动Flask服务
    print_info "以守护进程模式启动Flask服务..."
    nohup python3 run.py > logs/backend.log 2>&1 &
    
    # 保存PID
    PID=$!
    echo $PID > server.pid
    
    print_info "后端服务已启动 (PID: $PID)"
    
    # 返回上级目录
    cd ..
}

# 启动前端服务
start_frontend() {
    print_info "启动前端服务..."
    
    # 检查是否已经在运行
    if [ -f "backend/frontend.pid" ]; then
        PID=$(cat backend/frontend.pid)
        if ps -p $PID > /dev/null; then
            print_warn "前端服务已经在运行 (PID: $PID)"
            return
        else
            # 进程不存在但PID文件存在，删除PID文件
            rm backend/frontend.pid
        fi
    fi
    
    # 进入前端目录
    cd frontend
    
    # 启动React开发服务器
    print_info "以守护进程模式启动React开发服务器..."
    nohup npm start > ../backend/logs/frontend.log 2>&1 &
    
    # 保存PID
    PID=$!
    echo $PID > ../backend/frontend.pid
    
    print_info "前端服务已启动 (PID: $PID)"
    
    # 返回上级目录
    cd ..
}

# 检查服务状态
check_services() {
    print_info "检查服务状态..."
    
    # 检查后端服务
    if [ -f "backend/server.pid" ]; then
        PID=$(cat backend/server.pid)
        if ps -p $PID > /dev/null; then
            print_info "后端服务运行中 (PID: $PID)"
        else
            print_warn "后端服务PID文件存在，但进程未运行"
        fi
    else
        print_warn "后端服务未运行"
    fi
    
    # 检查前端服务
    if [ -f "backend/frontend.pid" ]; then
        PID=$(cat backend/frontend.pid)
        if ps -p $PID > /dev/null; then
            print_info "前端服务运行中 (PID: $PID)"
        else
            print_warn "前端服务PID文件存在，但进程未运行"
        fi
    else
        print_warn "前端服务未运行"
    fi
    
    # 检查Suricata
    if pidof -x suricata >/dev/null; then
        SURICATA_PID=$(pidof suricata)
        print_info "Suricata运行中 (PID: $SURICATA_PID)"
    else
        print_warn "Suricata未运行"
    fi
}

# 显示访问信息
show_access_info() {
    print_info "服务启动完成！"
    echo ""
    echo "==================================================="
    echo "  后端API地址: http://localhost:5000/api"
    echo "  前端Web界面: http://localhost:3000"
    echo "==================================================="
    echo ""
    print_info "可以通过浏览器访问系统界面"
    print_info "使用Ctrl+C停止前台进程，或运行./stop.sh脚本停止所有服务"
}

# 主函数
main() {
    print_info "正在启动基于Suricata的网络入侵检测系统..."
    
    # 检查环境
    check_requirements
    
    # 确保PID目录存在
    ensure_pid_dir
    
    # 启动服务
    start_suricata
    start_backend
    start_frontend
    
    # 检查服务状态
    check_services
    
    # 显示访问信息
    show_access_info
}

# 执行主函数
main 

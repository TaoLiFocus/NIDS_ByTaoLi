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

# 停止前端服务
stop_frontend() {
    print_info "停止前端服务..."
    
    if [ -f "backend/frontend.pid" ]; then
        PID=$(cat backend/frontend.pid)
        if ps -p $PID > /dev/null; then
            kill $PID
            print_info "前端服务已停止 (PID: $PID)"
        else
            print_warn "前端服务PID文件存在，但进程未运行"
        fi
        rm -f backend/frontend.pid
    else
        print_warn "未找到前端服务PID文件，尝试查找并终止进程..."
        # 尝试通过进程名查找并终止
        pkill -f "react-scripts start"
        pkill -f "node.*react-scripts start"
    fi
}

# 停止后端服务
stop_backend() {
    print_info "停止后端服务..."
    
    if [ -f "backend/server.pid" ]; then
        PID=$(cat backend/server.pid)
        if ps -p $PID > /dev/null; then
            kill $PID
            print_info "后端服务已停止 (PID: $PID)"
        else
            print_warn "后端服务PID文件存在，但进程未运行"
        fi
        rm -f backend/server.pid
    else
        print_warn "未找到后端服务PID文件，尝试查找并终止进程..."
        # 尝试通过进程名查找并终止
        pkill -f "python3 run.py"
    fi
}

# 停止Suricata
stop_suricata() {
    print_info "停止Suricata..."
    
    # 检查Suricata是否运行
    if pidof -x suricata >/dev/null; then
        SURICATA_PID=$(pidof suricata)
        print_info "尝试停止Suricata (PID: $SURICATA_PID)"
        
        # 使用sudo停止Suricata
        sudo kill $SURICATA_PID
        
        # 等待进程终止
        sleep 2
        
        # 检查是否成功停止
        if pidof -x suricata >/dev/null; then
            print_warn "Suricata未正常停止，尝试强制终止..."
            sudo kill -9 $(pidof suricata)
            sleep 1
        fi
        
        # 最终确认
        if ! pidof -x suricata >/dev/null; then
            print_info "Suricata已成功停止"
        else
            print_error "无法停止Suricata，请手动终止进程"
        fi
    else
        print_info "Suricata未运行"
    fi
}

# 检查服务状态
check_services() {
    print_info "检查剩余服务..."
    
    # 检查前端服务
    if pgrep -f "react-scripts start" > /dev/null || pgrep -f "node.*react-scripts start" > /dev/null; then
        print_warn "发现前端服务仍在运行，强制终止..."
        pkill -9 -f "react-scripts start"
        pkill -9 -f "node.*react-scripts start"
    fi
    
    # 检查后端服务
    if pgrep -f "python3 run.py" > /dev/null; then
        print_warn "发现后端服务仍在运行，强制终止..."
        pkill -9 -f "python3 run.py"
    fi
    
    # 检查Suricata
    if pidof -x suricata >/dev/null; then
        print_warn "发现Suricata仍在运行，强制终止..."
        sudo pkill -9 -x suricata
    fi
}

# 主函数
main() {
    print_info "正在停止基于Suricata的网络入侵检测系统..."
    
    # 停止服务
    stop_frontend
    stop_backend
    stop_suricata
    
    # 确认服务已停止
    sleep 2
    check_services
    
    print_info "所有服务已停止"
}

# 执行主函数
main 
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

# 停止Suricata服务
stop_suricata() {
    print_info "停止Suricata服务..."
    
    # 从.env文件加载配置
    if [ -f "backend/.env" ]; then
        source <(grep -v '^#' backend/.env | sed -E 's/(.*)=(.*)/export \1="\2"/g')
    fi
    
    # 使用PID文件停止
    if [ -f "./pids/suricata.pid" ]; then
        PID=$(cat ./pids/suricata.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_info "停止Suricata进程 PID: $PID"
            sudo kill $PID
        fi
        rm -f ./pids/suricata.pid
    fi
    
    # 检查是否还有运行的Suricata进程
    if pgrep -f "suricata" > /dev/null; then
        print_warn "Suricata进程仍在运行，尝试强制终止..."
        sudo pkill -9 -f "suricata"
    fi
    
    # 确认停止状态
    if ! pgrep -f "suricata" > /dev/null; then
        print_info "Suricata服务已停止"
    else
        print_error "无法停止Suricata服务，请手动终止进程"
    fi
}

# 停止后端服务
stop_backend() {
    print_info "停止后端服务..."
    
    # 使用PID文件停止
    if [ -f "./pids/backend.pid" ]; then
        PID=$(cat ./pids/backend.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_info "停止后端进程 PID: $PID"
            kill $PID
            sleep 2
            # 如果进程仍在运行，强制终止
            if ps -p $PID > /dev/null 2>&1; then
                print_warn "后端进程未响应，强制终止..."
                kill -9 $PID
            fi
        fi
        rm -f ./pids/backend.pid
    fi
    
    # 检查是否还有运行的Flask进程
    if pgrep -f "python run.py" > /dev/null; then
        print_warn "Flask进程仍在运行，尝试终止..."
        pkill -f "python run.py"
        sleep 1
        if pgrep -f "python run.py" > /dev/null; then
            print_warn "Flask进程未响应，强制终止..."
            pkill -9 -f "python run.py"
        fi
    fi
    
    # 确认停止状态
    if ! pgrep -f "python run.py" > /dev/null; then
        print_info "后端服务已停止"
    else
        print_error "无法停止后端服务，请手动终止进程"
    fi
}

# 停止前端服务
stop_frontend() {
    print_info "停止前端服务..."
    
    # 使用PID文件停止
    if [ -f "./pids/frontend.pid" ]; then
        PID=$(cat ./pids/frontend.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_info "停止前端进程 PID: $PID"
            kill $PID
            sleep 2
            # 如果进程仍在运行，强制终止
            if ps -p $PID > /dev/null 2>&1; then
                print_warn "前端进程未响应，强制终止..."
                kill -9 $PID
            fi
        fi
        rm -f ./pids/frontend.pid
    fi
    
    # 检查是否还有运行的npm进程
    if pgrep -f "react-scripts start" > /dev/null; then
        print_warn "React进程仍在运行，尝试终止..."
        pkill -f "react-scripts start"
        sleep 1
        if pgrep -f "react-scripts start" > /dev/null; then
            print_warn "React进程未响应，强制终止..."
            pkill -9 -f "react-scripts start"
        fi
    fi
    
    # 确认停止状态
    if ! pgrep -f "react-scripts start" > /dev/null; then
        print_info "前端服务已停止"
    else
        print_error "无法停止前端服务，请手动终止进程"
    fi
}

# 清理PID文件
cleanup_pid_files() {
    print_info "清理进程ID文件..."
    rm -f ./pids/*.pid
}

# 主函数
main() {
    print_info "开始停止NIDS系统..."
    
    # 停止各服务
    stop_frontend
    stop_backend
    stop_suricata
    
    # 清理PID文件
    cleanup_pid_files
    
    print_info "NIDS系统已完全停止"
}

# 执行主函数
main 
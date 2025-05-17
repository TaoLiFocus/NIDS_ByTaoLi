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

# 检查运行状态的函数
check_process() {
    pgrep -f "$1" > /dev/null
    return $?
}

# 清理旧的进程ID文件
cleanup_pid_files() {
    mkdir -p ./pids
    rm -f ./pids/*.pid
}

# 启动Suricata
start_suricata() {
    print_info "启动Suricata服务..."
    
    # 检查.env文件
    if [ ! -f "backend/.env" ]; then
        print_error "未找到环境配置文件 backend/.env"
        exit 1
    fi
    
    # 从.env文件加载配置
    source <(grep -v '^#' backend/.env | sed -E 's/(.*)=(.*)/export \1="\2"/g')
    
    # 检查网络接口设置
    if [ -z "$INTERFACE" ]; then
        INTERFACE="ens33"
        print_warn "未指定网络接口，使用默认接口: $INTERFACE"
    fi
    
    # 检查Suricata配置文件
    if [ ! -f "$SURICATA_CONFIG" ]; then
        print_error "未找到Suricata配置文件: $SURICATA_CONFIG"
        exit 1
    fi
    
    # 删除过期的PID文件
    if [ -f "/var/run/suricata.pid" ]; then
        print_warn "发现过期的Suricata PID文件，正在删除..."
        sudo rm -f /var/run/suricata.pid
    fi
    
    # 启动Suricata
    print_info "使用接口 $INTERFACE 启动Suricata..."
    sudo pkill -f "suricata -c $SURICATA_CONFIG" > /dev/null 2>&1 || true
    sudo suricata -c $SURICATA_CONFIG --af-packet=$INTERFACE -D
    
    # 检查是否启动成功
    sleep 2
    if pgrep -f "suricata" > /dev/null; then
        print_info "Suricata 服务已启动"
        pgrep -f "suricata" > ./pids/suricata.pid
    else
        print_error "Suricata 服务启动失败"
        exit 1
    fi
}

# 启动前端服务
start_frontend() {
    print_info "启动前端服务..."
    
    # 检查前端目录
    if [ ! -d "frontend" ]; then
        print_error "未找到前端目录"
        exit 1
    fi
    
    # 启动前端
    cd frontend
    nohup npm start > ../logs/frontend.log 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > ../pids/frontend.pid
    
    # 检查是否启动成功
    sleep 5
    if ps -p $FRONTEND_PID > /dev/null; then
        print_info "前端服务已启动，PID: $FRONTEND_PID"
    else
        print_error "前端服务启动失败"
        cat ../logs/frontend.log
        exit 1
    fi
    
    cd ..
}

# 主函数
main() {
    print_info "开始启动基本NIDS系统..."
    
    # 创建日志目录
    mkdir -p logs
    # 清理旧的PID文件
    cleanup_pid_files
    
    # 启动各服务
    start_suricata
    start_frontend
    
    print_info "基本NIDS系统启动完成！"
    print_info "前端服务运行在: http://localhost:3000/"
    print_info "使用以下命令停止服务:"
    print_info "  ./stop.sh"
    print_info "注意: 后端服务未启动，某些功能可能不可用。"
}

# 执行主函数
main 
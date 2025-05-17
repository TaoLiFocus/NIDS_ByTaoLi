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

# 启动后端服务
start_backend() {
    print_info "启动后端服务..."
    
    # 检查后端目录
    if [ ! -d "backend" ]; then
        print_error "未找到后端目录"
        exit 1
    fi
    
    # 检查Python虚拟环境
    cd backend
    if [ ! -d "venv" ]; then
        print_warn "虚拟环境不存在，尝试创建..."
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
        if [ $? -ne 0 ]; then
            print_error "安装依赖失败，请检查requirements.txt"
            exit 1
        fi
    else
        source venv/bin/activate
    fi
    
    # 启动后端
    print_info "在虚拟环境中启动Flask应用..."
    nohup python run.py > ../logs/backend.log 2>&1 &
    BACKEND_PID=$!
    echo $BACKEND_PID > ../pids/backend.pid
    
    # 检查是否启动成功
    sleep 5
    if ps -p $BACKEND_PID > /dev/null; then
        print_info "后端服务已启动，PID: $BACKEND_PID"
    else
        print_error "后端服务启动失败"
        cat ../logs/backend.log
        exit 1
    fi
    
    # 退出虚拟环境
    deactivate
    cd ..
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

# 检查端口占用
check_port_usage() {
    print_info "检查端口占用..."
    
    # 检查后端端口 (5000)
    if lsof -i:5000 > /dev/null 2>&1; then
        print_warn "端口5000已被占用，尝试终止进程..."
        sudo kill -9 $(lsof -t -i:5000) 2>/dev/null || true
    fi
    
    # 检查前端端口 (3000)
    if lsof -i:3000 > /dev/null 2>&1; then
        print_warn "端口3000已被占用，尝试终止进程..."
        sudo kill -9 $(lsof -t -i:3000) 2>/dev/null || true
    fi
    
    print_info "端口检查完成"
}

# 主函数
main() {
    print_info "开始启动完整NIDS系统..."
    
    # 创建日志目录
    mkdir -p logs
    # 清理旧的PID文件
    cleanup_pid_files
    # 检查端口占用
    check_port_usage
    
    # 启动各服务
    start_suricata
    start_backend
    start_frontend
    
    print_info "NIDS系统启动完成！"
    print_info "后端服务运行在: http://localhost:5000/"
    print_info "前端服务运行在: http://localhost:3000/"
    print_info "使用以下命令停止服务:"
    print_info "  ./stop.sh"
}

# 执行主函数
main 
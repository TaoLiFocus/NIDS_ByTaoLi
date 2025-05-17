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

# 创建并激活虚拟环境
setup_venv() {
    print_info "创建Python虚拟环境..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    print_info "成功创建并激活虚拟环境"
}

# 安装依赖
install_deps() {
    print_info "安装兼容版本的依赖..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        print_error "安装依赖失败"
        exit 1
    fi
    print_info "依赖安装完成"
}

# 修复run.py
fix_runpy() {
    print_info "修复run.py文件..."
    cat > run.py << EOF
import os
from app import create_app
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 创建应用
app = create_app(os.getenv('FLASK_CONFIG') or 'default')

if __name__ == '__main__':
    # 使用Flask内置服务器启动
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF
    print_info "run.py修复完成"
}

# 修复app/__init__.py
fix_init() {
    print_info "修复app/__init__.py文件..."
    # 创建备份
    if [ -f "app/__init__.py" ]; then
        cp app/__init__.py app/__init__.py.bak
        
        # 移除socketio初始化
        sed -i 's/socketio\.init_app.*/# socketio功能已禁用/' app/__init__.py
        print_info "app/__init__.py修复完成"
    else
        print_warn "app/__init__.py不存在，跳过修复"
    fi
}

# 主函数
main() {
    print_info "开始修复后端服务..."
    
    # 进入后端目录
    cd backend || { print_error "后端目录不存在"; exit 1; }
    
    # 设置虚拟环境
    setup_venv
    
    # 安装依赖
    install_deps
    
    # 修复文件
    fix_runpy
    fix_init
    
    # 返回主目录
    cd ..
    
    print_info "后端服务修复完成！"
    print_info "现在可以使用以下命令启动完整系统:"
    print_info "cd backend && source venv/bin/activate && python run.py"
}

# 执行主函数
main 
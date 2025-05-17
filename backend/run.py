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

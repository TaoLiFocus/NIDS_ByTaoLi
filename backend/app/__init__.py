from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_mail import Mail
import os
import logging
from logging.handlers import RotatingFileHandler

from .config import config
from .database import init_db

# 初始化插件
jwt = JWTManager()
mail = Mail()
socketio = SocketIO()

def setup_logging(app):
    """设置日志"""
    # 确保日志目录存在
    log_dir = os.path.join(os.path.dirname(app.root_path), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 配置日志格式
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # 文件处理器 - 保存到文件
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # 控制台处理器 - 输出到控制台
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # 设置Flask日志
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)
    
    # 设置PCAP处理模块的日志
    pcap_logger = logging.getLogger('app.pcap')
    pcap_logger.addHandler(file_handler)
    pcap_logger.addHandler(console_handler)
    pcap_logger.setLevel(logging.INFO)
    
    # 记录应用启动信息
    app.logger.info('应用已启动')

def create_app(config_name='default'):
    """创建Flask应用"""
    # 创建应用
    app = Flask(__name__)
    
    # 加载配置
    app.config.from_object(config[config_name])
    
    # 确保上传目录存在
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # 设置日志
    setup_logging(app)
    
    # 初始化插件
    jwt.init_app(app)
    CORS(app)
    mail.init_app(app)
    # socketio功能已禁用
    
    # 初始化数据库
    init_db(app)
    
    # 注册蓝图
    from .auth.routes import auth_bp
    from .monitor.routes import monitor_bp
    from .pcap.routes import pcap_bp
    from .settings.routes import settings_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(monitor_bp, url_prefix='/api/monitor')
    app.register_blueprint(pcap_bp, url_prefix='/api/pcap')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    
    # 注册错误处理
    register_error_handlers(app)
    
    return app

def register_error_handlers(app):
    """注册错误处理器"""
    @app.errorhandler(404)
    def not_found(e):
        return {'message': '找不到请求的资源'}, 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f'服务器内部错误: {str(e)}')
        return {'message': '服务器内部错误'}, 500

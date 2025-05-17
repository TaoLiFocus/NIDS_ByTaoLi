import os
from datetime import timedelta

class Config:
    # Flask配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG') or True
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://root:root@localhost/nids_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT配置
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # 邮件配置
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.163.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 465)
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL') or True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'your_email@163.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your_password'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'your_email@163.com'
    
    # Suricata配置
    SURICATA_BIN = os.environ.get('SURICATA_BIN') or '/usr/bin/suricata'
    SURICATA_RULES_DIR = os.environ.get('SURICATA_RULES_DIR') or '/etc/suricata/rules'
    SURICATA_CONFIG = os.environ.get('SURICATA_CONFIG') or '/etc/suricata/suricata.yaml'
    SURICATA_LOG_DIR = os.environ.get('SURICATA_LOG_DIR') or '/var/log/suricata'
    SURICATA_EVE_JSON = os.environ.get('SURICATA_EVE_JSON') or '/var/log/suricata/eve.json'
    
    # 上传文件配置
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # 网络接口配置
    INTERFACE = os.environ.get('INTERFACE') or 'eth0'
    
    # WebSocket配置
    SOCKETIO_ASYNC_MODE = 'eventlet'

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 
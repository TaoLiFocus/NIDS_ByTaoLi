from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """初始化数据库连接"""
    db.init_app(app)
    
    # 在应用上下文中创建所有表
    with app.app_context():
        db.create_all() 
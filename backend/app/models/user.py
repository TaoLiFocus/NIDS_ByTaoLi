from datetime import datetime
import bcrypt
from ..database import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # admin, user
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, username, email, password, role='user'):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role
    
    def set_password(self, password):
        """设置密码哈希"""
        # 确保输入是utf-8编码的字节
        if isinstance(password, str):
            password = password.encode('utf-8')
        # 生成salt并哈希密码
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password, salt)
        # 将哈希结果存储为字符串
        self.password_hash = password_hash.decode('utf-8')
    
    def check_password(self, password):
        """验证密码"""
        try:
            # 确保输入是utf-8编码的字节
            if isinstance(password, str):
                password = password.encode('utf-8')
            # 读取存储的哈希值
            stored_hash = self.password_hash
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')
            # 验证密码
            return bcrypt.checkpw(password, stored_hash)
        except ValueError:
            # 如果哈希格式错误，返回False
            return False
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<User {self.username}>' 
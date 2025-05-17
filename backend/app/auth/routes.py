from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token,
    get_jwt_identity,
    jwt_required
)
from datetime import datetime
import random
import string
from ..models.user import User
from ..database import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """注册新用户"""
    data = request.get_json()
    
    # 验证请求数据
    if not data or not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'message': '缺少必要字段'}), 400
    
    # 检查用户名是否已存在
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': '用户名已存在'}), 409
    
    # 检查邮箱是否已存在
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': '邮箱已存在'}), 409
    
    # 创建新用户
    try:
        user = User(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': '注册成功',
            'user': user.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'注册失败: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.get_json()
    
    # 验证请求数据
    if not data or not all(k in data for k in ('username', 'password')):
        return jsonify({'message': '缺少必要字段'}), 400
    
    # 查找用户
    user = User.query.filter_by(username=data['username']).first()
    
    # 验证用户和密码
    if not user or not user.check_password(data['password']):
        return jsonify({'message': '用户名或密码错误'}), 401
    
    # 检查账户状态
    if not user.is_active:
        return jsonify({'message': '账户已禁用'}), 403
    
    # 生成JWT令牌
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'message': '登录成功',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """刷新访问令牌"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_active:
        return jsonify({'message': '账户不存在或已禁用'}), 403
    
    access_token = create_access_token(identity=str(current_user_id))
    
    return jsonify({
        'access_token': access_token
    }), 200

@auth_bp.route('/reset-password-request', methods=['POST'])
def reset_password_request():
    """密码重置请求"""
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'message': '缺少邮箱字段'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        # 为了安全，即使用户不存在也返回成功
        return jsonify({'message': '如果邮箱存在，重置链接将发送到您的邮箱'}), 200
    
    # 生成验证码
    verification_code = ''.join(random.choices(string.digits, k=6))
    
    # TODO: 发送验证码邮件
    # 这里简化处理，实际应用中应该发送邮件
    # 在实际应用中，应该将验证码存储到数据库或缓存中，并设置过期时间
    
    # 模拟存储验证码
    # 在实际应用中，应该使用Redis等缓存存储
    user.verification_code = verification_code
    user.verification_code_expires = datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    db.session.commit()
    
    return jsonify({'message': '如果邮箱存在，重置链接将发送到您的邮箱'}), 200

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """重置密码"""
    data = request.get_json()
    
    if not data or not all(k in data for k in ('email', 'verification_code', 'new_password')):
        return jsonify({'message': '缺少必要字段'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'message': '用户不存在'}), 404
    
    # 验证码验证
    # 在实际应用中，应该从Redis等缓存中获取验证码
    if not hasattr(user, 'verification_code') or user.verification_code != data['verification_code']:
        return jsonify({'message': '验证码错误'}), 400
    
    # 验证码过期验证
    if not hasattr(user, 'verification_code_expires') or datetime.utcnow() > user.verification_code_expires:
        return jsonify({'message': '验证码已过期'}), 400
    
    # 更新密码
    user.set_password(data['new_password'])
    
    # 清除验证码
    if hasattr(user, 'verification_code'):
        delattr(user, 'verification_code')
    if hasattr(user, 'verification_code_expires'):
        delattr(user, 'verification_code_expires')
    
    db.session.commit()
    
    return jsonify({'message': '密码重置成功'}), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """获取用户信息"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': '用户不存在'}), 404
    
    return jsonify({
        'user': user.to_dict()
    }), 200

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """修改密码"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': '用户不存在'}), 404
    
    data = request.get_json()
    
    if not data or not all(k in data for k in ('old_password', 'new_password')):
        return jsonify({'message': '缺少必要字段'}), 400
    
    if not user.check_password(data['old_password']):
        return jsonify({'message': '原密码错误'}), 401
    
    # 更新密码
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': '密码修改成功'}), 200 
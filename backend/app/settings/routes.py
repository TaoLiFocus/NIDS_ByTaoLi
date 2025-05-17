from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import os
import shutil
from ..models.setting import Setting, Rule
from ..models.user import User
from ..database import db

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/rules', methods=['GET'])
@jwt_required()
def get_rules():
    """获取所有Suricata规则"""
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 查询规则
    pagination = Rule.query.order_by(Rule.updated_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    rules = [rule.to_dict() for rule in pagination.items]
    
    return jsonify({
        'rules': rules,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
        'per_page': per_page
    }), 200

@settings_bp.route('/rules/<int:rule_id>', methods=['GET'])
@jwt_required()
def get_rule(rule_id):
    """获取特定规则"""
    rule = Rule.query.get_or_404(rule_id)
    return jsonify(rule.to_dict()), 200

@settings_bp.route('/rules', methods=['POST'])
@jwt_required()
def create_rule():
    """创建新规则"""
    # 验证是否为管理员
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'message': '需要管理员权限'}), 403
    
    data = request.get_json()
    
    # 验证请求数据
    if not data or not all(k in data for k in ('name', 'content')):
        return jsonify({'message': '缺少必要字段'}), 400
    
    # 创建新规则
    try:
        rule = Rule(
            name=data['name'],
            content=data['content'],
            is_enabled=data.get('is_enabled', True),
            description=data.get('description', '')
        )
        
        db.session.add(rule)
        db.session.commit()
        
        # 将规则写入规则文件
        rule_file_path = os.path.join(
            current_app.config['SURICATA_RULES_DIR'], 
            f"rule_{rule.id}.rules"
        )
        
        with open(rule_file_path, 'w') as f:
            f.write(rule.content)
        
        return jsonify({
            'message': '规则创建成功',
            'rule': rule.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'规则创建失败: {str(e)}'}), 500

@settings_bp.route('/rules/<int:rule_id>', methods=['PUT'])
@jwt_required()
def update_rule(rule_id):
    """更新规则"""
    # 验证是否为管理员
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'message': '需要管理员权限'}), 403
    
    rule = Rule.query.get_or_404(rule_id)
    data = request.get_json()
    
    # 更新规则
    try:
        if 'name' in data:
            rule.name = data['name']
        if 'content' in data:
            rule.content = data['content']
        if 'is_enabled' in data:
            rule.is_enabled = data['is_enabled']
        if 'description' in data:
            rule.description = data['description']
        
        db.session.commit()
        
        # 更新规则文件
        rule_file_path = os.path.join(
            current_app.config['SURICATA_RULES_DIR'], 
            f"rule_{rule.id}.rules"
        )
        
        # 如果规则被禁用，则删除文件
        if not rule.is_enabled and os.path.exists(rule_file_path):
            os.remove(rule_file_path)
        # 如果规则被启用，则更新文件
        elif rule.is_enabled:
            with open(rule_file_path, 'w') as f:
                f.write(rule.content)
        
        return jsonify({
            'message': '规则更新成功',
            'rule': rule.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'规则更新失败: {str(e)}'}), 500

@settings_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@jwt_required()
def delete_rule(rule_id):
    """删除规则"""
    # 验证是否为管理员
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'message': '需要管理员权限'}), 403
    
    rule = Rule.query.get_or_404(rule_id)
    
    # 删除规则
    try:
        db.session.delete(rule)
        db.session.commit()
        
        # 删除规则文件
        rule_file_path = os.path.join(
            current_app.config['SURICATA_RULES_DIR'], 
            f"rule_{rule.id}.rules"
        )
        
        if os.path.exists(rule_file_path):
            os.remove(rule_file_path)
        
        return jsonify({
            'message': '规则删除成功'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'规则删除失败: {str(e)}'}), 500

@settings_bp.route('/config', methods=['GET'])
@jwt_required()
def get_settings():
    """获取系统设置"""
    settings = Setting.query.all()
    return jsonify({
        'settings': [setting.to_dict() for setting in settings]
    }), 200

@settings_bp.route('/config/<key>', methods=['GET'])
@jwt_required()
def get_setting(key):
    """获取特定设置"""
    setting = Setting.query.filter_by(key=key).first_or_404()
    return jsonify(setting.to_dict()), 200

@settings_bp.route('/config', methods=['PUT'])
@jwt_required()
def update_settings():
    """更新系统设置"""
    # 验证是否为管理员
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'message': '需要管理员权限'}), 403
    
    data = request.get_json()
    
    if not data or not isinstance(data, dict):
        return jsonify({'message': '无效的请求数据'}), 400
    
    updated_settings = []
    
    # 使用事务更新设置
    try:
        for key, value in data.items():
            setting = Setting.query.filter_by(key=key).first()
            
            if setting:
                # 更新现有设置
                setting.value = value
            else:
                # 创建新设置
                setting = Setting(key=key, value=value)
                db.session.add(setting)
            
            updated_settings.append(setting)
        
        db.session.commit()
        
        return jsonify({
            'message': '设置更新成功',
            'settings': [setting.to_dict() for setting in updated_settings]
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'设置更新失败: {str(e)}'}), 500

@settings_bp.route('/restart-suricata', methods=['POST'])
@jwt_required()
def restart_suricata():
    """重启Suricata服务"""
    # 验证是否为管理员
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'message': '需要管理员权限'}), 403
    
    try:
        # 停止现有的Suricata服务
        from ..monitor.routes import stop_monitoring, start_monitoring
        
        stop_monitoring()
        start_monitoring()
        
        return jsonify({
            'message': 'Suricata服务已重启'
        }), 200
    except Exception as e:
        return jsonify({'message': f'重启Suricata服务失败: {str(e)}'}), 500 
from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required
from flask_socketio import emit
import subprocess
import threading
import json
import os
import time
from ..models.alert import Alert
from ..database import db

monitor_bp = Blueprint('monitor', __name__)

# 全局变量，用于控制Suricata监控线程
suricata_running = False
suricata_process = None
monitor_thread = None

def start_suricata(interface):
    """启动Suricata监控特定网卡"""
    global suricata_process
    
    # 确保日志目录存在
    if not os.path.exists(current_app.config['SURICATA_LOG_DIR']):
        os.makedirs(current_app.config['SURICATA_LOG_DIR'])
    
    # 构建Suricata命令
    cmd = [
        current_app.config['SURICATA_BIN'],
        '-c', current_app.config['SURICATA_CONFIG'],
        '-i', interface,
        '--set', f'outputs.eve-log.filename={current_app.config["SURICATA_EVE_JSON"]}'
    ]
    
    # 启动Suricata进程
    try:
        suricata_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return True
    except Exception as e:
        current_app.logger.error(f"启动Suricata失败: {str(e)}")
        return False

def monitor_eve_log(socketio):
    """监控eve.json日志文件并推送告警"""
    global suricata_running
    
    eve_log_path = current_app.config['SURICATA_EVE_JSON']
    
    # 等待日志文件创建
    while not os.path.exists(eve_log_path) and suricata_running:
        time.sleep(1)
    
    # 如果日志文件未创建，则退出
    if not os.path.exists(eve_log_path):
        return
    
    # 打开日志文件并监控
    with open(eve_log_path, 'r') as f:
        # 移动到文件末尾
        f.seek(0, 2)
        
        while suricata_running:
            line = f.readline()
            
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                # 解析JSON日志
                log_entry = json.loads(line)
                
                # 检查是否为告警
                if 'alert' in log_entry:
                    # 创建告警记录
                    alert = Alert()
                    
                    # 设置基本属性
                    if 'timestamp' in log_entry:
                        alert.timestamp = log_entry['timestamp']
                    
                    # 设置告警信息
                    if 'alert' in log_entry:
                        alert_data = log_entry['alert']
                        alert.alert_action = alert_data.get('action')
                        alert.alert_gid = alert_data.get('gid')
                        alert.alert_signature_id = alert_data.get('signature_id')
                        alert.alert_rev = alert_data.get('rev')
                        alert.alert_signature = alert_data.get('signature')
                        alert.alert_category = alert_data.get('category')
                        alert.alert_severity = alert_data.get('severity')
                    
                    # 设置网络信息
                    if 'src_ip' in log_entry:
                        alert.src_ip = log_entry['src_ip']
                    if 'dest_ip' in log_entry:
                        alert.dest_ip = log_entry['dest_ip']
                    if 'src_port' in log_entry:
                        alert.src_port = log_entry['src_port']
                    if 'dest_port' in log_entry:
                        alert.dest_port = log_entry['dest_port']
                    if 'proto' in log_entry:
                        alert.proto = log_entry['proto']
                    
                    # 设置应用协议
                    if 'app_proto' in log_entry:
                        alert.app_proto = log_entry['app_proto']
                    
                    # 保存到数据库
                    db.session.add(alert)
                    db.session.commit()
                    
                    # 通过WebSocket推送给客户端
                    socketio.emit('new_alert', alert.to_dict(), namespace='/alerts')
                    
            except json.JSONDecodeError:
                # 忽略非JSON行
                continue
            except Exception as e:
                current_app.logger.error(f"处理告警失败: {str(e)}")
                continue

@monitor_bp.route('/start', methods=['POST'])
@jwt_required()
def start_monitoring():
    """启动网络监控"""
    global suricata_running, monitor_thread
    
    if suricata_running:
        return jsonify({'message': '监控已经在运行中'}), 400
    
    # 获取要监控的网络接口
    interface = current_app.config['INTERFACE']
    
    # 启动Suricata
    if not start_suricata(interface):
        return jsonify({'message': '启动Suricata失败'}), 500
    
    # 标记为运行中
    suricata_running = True
    
    # 启动监控线程
    from app import socketio  # 导入socketio实例
    monitor_thread = threading.Thread(
        target=monitor_eve_log,
        args=(socketio,)
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return jsonify({
        'message': f'已启动对接口 {interface} 的监控'
    }), 200

@monitor_bp.route('/stop', methods=['POST'])
@jwt_required()
def stop_monitoring():
    """停止网络监控"""
    global suricata_running, suricata_process
    
    if not suricata_running:
        return jsonify({'message': '监控未运行'}), 400
    
    # 停止监控线程
    suricata_running = False
    
    # 停止Suricata进程
    if suricata_process:
        suricata_process.terminate()
        suricata_process.wait()
        suricata_process = None
    
    return jsonify({
        'message': '已停止监控'
    }), 200

@monitor_bp.route('/status', methods=['GET'])
@jwt_required()
def monitoring_status():
    """获取监控状态"""
    return jsonify({
        'is_running': suricata_running
    }), 200

@monitor_bp.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    """获取告警列表"""
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 查询告警
    pagination = Alert.query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    alerts = [alert.to_dict() for alert in pagination.items]
    
    return jsonify({
        'alerts': alerts,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
        'per_page': per_page
    }), 200

@monitor_bp.route('/alerts/summary', methods=['GET'])
@jwt_required()
def get_alerts_summary():
    """获取告警摘要统计"""
    # 最近告警数量
    recent_count = Alert.query.count()
    
    # 严重级别统计
    severity_stats = db.session.query(
        Alert.alert_severity, 
        db.func.count(Alert.id)
    ).group_by(Alert.alert_severity).all()
    severity_data = {
        str(severity): count for severity, count in severity_stats
    }
    
    # 攻击类别统计
    category_stats = db.session.query(
        Alert.alert_category, 
        db.func.count(Alert.id)
    ).group_by(Alert.alert_category).order_by(
        db.func.count(Alert.id).desc()
    ).limit(5).all()
    category_data = {
        category: count for category, count in category_stats
    }
    
    # 源IP统计
    src_ip_stats = db.session.query(
        Alert.src_ip, 
        db.func.count(Alert.id)
    ).group_by(Alert.src_ip).order_by(
        db.func.count(Alert.id).desc()
    ).limit(5).all()
    src_ip_data = {
        ip: count for ip, count in src_ip_stats
    }
    
    return jsonify({
        'total_alerts': recent_count,
        'severity_stats': severity_data,
        'category_stats': category_data,
        'src_ip_stats': src_ip_data
    }), 200 
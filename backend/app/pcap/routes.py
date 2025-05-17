from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
import os
import uuid
import subprocess
import json
import shutil
from datetime import datetime
import magic  # 用于文件类型检测
from ..models.alert import Alert
from ..database import db

pcap_bp = Blueprint('pcap', __name__)

def allowed_file(filename):
    """检查文件类型是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pcap', 'pcapng', 'cap'}

def validate_pcap_content(file_path):
    """验证文件内容是否为PCAP格式"""
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type in ['application/vnd.tcpdump.pcap', 'application/octet-stream']

def analyze_pcap_with_suricata(pcap_file, output_dir):
    """使用Suricata分析PCAP文件"""
    eve_json = os.path.join(output_dir, 'eve.json')
    
    # 构建Suricata命令
    cmd = [
        current_app.config['SURICATA_BIN'],
        '-c', current_app.config['SURICATA_CONFIG'],
        '-r', pcap_file,
        '--set', f'outputs.eve-log.filename={eve_json}'
    ]
    
    # 执行命令
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            current_app.logger.error(f"Suricata分析失败: {stderr.decode('utf-8')}")
            return None
        
        return eve_json
    except Exception as e:
        current_app.logger.error(f"执行Suricata命令失败: {str(e)}")
        return None

def process_alerts_from_eve(eve_json, pcap_filename):
    """从eve.json中处理告警并存储到数据库"""
    alerts = []
    
    if not os.path.exists(eve_json):
        return [], "Eve.json文件不存在"
    
    try:
        with open(eve_json, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line)
                    
                    # 只处理告警事件
                    if 'alert' in log_entry:
                        # 创建告警记录
                        alert = Alert()
                        
                        # 设置基本属性
                        if 'timestamp' in log_entry:
                            alert.timestamp = datetime.strptime(
                                log_entry['timestamp'].split('+')[0], 
                                '%Y-%m-%dT%H:%M:%S.%f'
                            )
                        
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
                        
                        # 设置PCAP文件名
                        alert.pcap_filename = pcap_filename
                        
                        # 保存到数据库
                        db.session.add(alert)
                        alerts.append(alert)
                        
                except json.JSONDecodeError:
                    # 忽略非JSON行
                    continue
                except Exception as e:
                    current_app.logger.error(f"处理告警行失败: {str(e)}")
                    continue
            
            # 提交所有告警
            if alerts:
                db.session.commit()
            
        return alerts, None
    except Exception as e:
        db.session.rollback()
        return [], f"处理告警失败: {str(e)}"

@pcap_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_pcap():
    """上传PCAP文件并进行分析"""
    # 检查是否有文件上传
    if 'file' not in request.files:
        return jsonify({'message': '没有文件上传'}), 400
    
    file = request.files['file']
    
    # 检查文件名是否为空
    if file.filename == '':
        return jsonify({'message': '未选择文件'}), 400
    
    # 检查文件类型
    if not allowed_file(file.filename):
        return jsonify({'message': '不支持的文件类型，仅支持PCAP格式'}), 400
    
    # 创建上传文件目录
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    
    # 生成唯一文件名
    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    unique_filename = f"{unique_id}_{filename}"
    file_path = os.path.join(upload_folder, unique_filename)
    
    # 保存文件
    file.save(file_path)
    
    # 验证文件内容
    if not validate_pcap_content(file_path):
        os.remove(file_path)
        return jsonify({'message': '文件内容不是有效的PCAP格式'}), 400
    
    # 创建分析输出目录
    output_dir = os.path.join(upload_folder, unique_id)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 使用Suricata分析PCAP
    eve_json = analyze_pcap_with_suricata(file_path, output_dir)
    
    if not eve_json:
        shutil.rmtree(output_dir, ignore_errors=True)
        return jsonify({'message': 'Suricata分析失败'}), 500
    
    # 处理告警
    alerts, error = process_alerts_from_eve(eve_json, unique_filename)
    
    if error:
        shutil.rmtree(output_dir, ignore_errors=True)
        return jsonify({'message': error}), 500
    
    # 计算统计数据
    alert_count = len(alerts)
    
    # 获取TOP5威胁类型
    top_threats = {}
    for alert in alerts:
        category = alert.alert_category
        if category in top_threats:
            top_threats[category] += 1
        else:
            top_threats[category] = 1
    
    # 转换为列表并排序
    top_threats_list = sorted(
        [{'category': k, 'count': v} for k, v in top_threats.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:5]
    
    # 清理分析目录
    shutil.rmtree(output_dir, ignore_errors=True)
    
    return jsonify({
        'message': '文件上传并分析成功',
        'filename': unique_filename,
        'alert_count': alert_count,
        'top_threats': top_threats_list
    }), 200

@pcap_bp.route('/list', methods=['GET'])
@jwt_required()
def list_pcap_files():
    """获取上传的PCAP文件列表"""
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 查询PCAP文件关联的告警
    pcap_files = db.session.query(
        Alert.pcap_filename, 
        db.func.count(Alert.id).label('alert_count'),
        db.func.min(Alert.timestamp).label('upload_time')
    ).filter(
        Alert.pcap_filename.isnot(None)
    ).group_by(
        Alert.pcap_filename
    ).order_by(
        db.func.min(Alert.timestamp).desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    result = [{
        'filename': item[0],
        'alert_count': item[1],
        'upload_time': item[2].isoformat() if item[2] else None
    } for item in pcap_files.items]
    
    return jsonify({
        'pcap_files': result,
        'total': pcap_files.total,
        'pages': pcap_files.pages,
        'page': page,
        'per_page': per_page
    }), 200

@pcap_bp.route('/<filename>/alerts', methods=['GET'])
@jwt_required()
def get_pcap_alerts(filename):
    """获取特定PCAP文件的告警"""
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 查询告警
    pagination = Alert.query.filter_by(
        pcap_filename=filename
    ).order_by(
        Alert.timestamp.desc()
    ).paginate(
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
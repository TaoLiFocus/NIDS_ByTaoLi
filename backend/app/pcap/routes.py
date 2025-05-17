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
from ..models.pcap import PcapFile
from ..database import db
from .utils import check_pcap_format, convert_pcap_format
import re

pcap_bp = Blueprint('pcap', __name__)

def allowed_file(filename):
    """检查文件类型是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pcap', 'pcapng', 'cap'}

def validate_pcap_content(file_path):
    """验证文件内容是否为PCAP格式"""
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type in ['application/vnd.tcpdump.pcap', 'application/octet-stream']

def analyze_pcap_with_suricata(pcap_file, output_dir, eve_filename='eve.json'):
    """使用Suricata分析PCAP文件"""
    # 确保使用绝对路径
    pcap_file = os.path.abspath(pcap_file)
    output_dir = os.path.abspath(output_dir)
    eve_json = os.path.join(output_dir, eve_filename)
    
    current_app.logger.info(f"使用Suricata分析PCAP文件: {pcap_file}")
    
    # 检查文件是否存在
    if not os.path.exists(pcap_file):
        error_msg = f"分析前检查PCAP文件不存在: {pcap_file}"
        current_app.logger.error(error_msg)
        return None, error_msg
    
    # 检查是否有读取权限
    if not os.access(pcap_file, os.R_OK):
        error_msg = f"没有PCAP文件的读取权限: {pcap_file}"
        current_app.logger.error(error_msg)
        return None, error_msg
    
    # 检查PCAP文件大小
    file_size = os.path.getsize(pcap_file)
    if file_size == 0:
        error_msg = "PCAP文件为空"
        current_app.logger.error(error_msg)
        return None, error_msg
    else:
        current_app.logger.info(f"PCAP文件大小: {file_size} 字节")
    
    # ==== 直接模式 - 使用与手动相同的命令（已知可以成功） ====
    # 不检查PCAP格式，不进行转换，直接用已知可以工作的命令
    try:
        # 使用与手动命令完全相同的参数
        cmd = [
            "/usr/bin/suricata",  # 固定路径，不使用配置
            "-c", "/etc/suricata/suricata.yaml",  # 固定配置路径
            "-r", pcap_file,
            "-v",
            "-k", "none"  # 忽略校验和错误
        ]
        current_app.logger.info(f"使用直接模式命令: {' '.join(cmd)}")
        
        # 执行命令
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(pcap_file)  # 在文件所在目录运行
        )
        stdout, stderr = process.communicate()
        
        stdout_text = stdout.decode('utf-8')
        stderr_text = stderr.decode('utf-8')
        
        if stdout_text:
            current_app.logger.info(f"Suricata输出: {stdout_text[:500]}...")
        if stderr_text:
            current_app.logger.info(f"Suricata错误: {stderr_text[:500]}...")
        
        current_app.logger.info(f"Suricata返回码: {process.returncode}")
        
        # 处理结果
        if process.returncode == 0:  # 成功
            # 默认的eve.json位置
            system_eve = '/var/log/suricata/eve.json'
            if os.path.exists(system_eve):
                try:
                    current_app.logger.info(f"从{system_eve}复制结果到{eve_json}")
                    shutil.copy2(system_eve, eve_json)
                    return eve_json, None
                except Exception as e:
                    current_app.logger.error(f"复制结果文件失败: {str(e)}")
                    return None, f"分析成功但复制结果失败: {str(e)}"
            else:
                current_app.logger.error(f"Suricata未生成结果文件: {system_eve}")
                return None, "Suricata未生成结果文件"
        else:
            # 如果直接模式失败，尝试使用应急模式
            current_app.logger.warning(f"直接模式失败（返回码 {process.returncode}），尝试使用应急模式...")
            success, error, eve_output = try_suricata_analysis(pcap_file, eve_json, mode="emergency")
            if success:
                return eve_output, None
            else:
                return None, f"Suricata分析失败: 返回码 {process.returncode}，应急模式也失败: {error}"
    except Exception as e:
        current_app.logger.error(f"直接模式执行失败: {str(e)}")
        # 尝试应急模式
        current_app.logger.warning(f"直接模式异常，尝试使用应急模式...")
        success, error, eve_output = try_suricata_analysis(pcap_file, eve_json, mode="emergency")
        if success:
            return eve_output, None
        else:
            return None, f"执行失败: {str(e)}，应急模式也失败: {error}"

def try_suricata_analysis(pcap_file, eve_json, mode="default"):
    """尝试使用不同模式运行Suricata分析
    
    参数:
        pcap_file: PCAP文件路径
        eve_json: 输出JSON文件路径
        mode: 运行模式 (default, safe, minimal, emergency)
        
    返回:
        (bool, str, str): 成功标志, 错误消息, 输出文件路径
    """
    # 确保输出目录存在
    output_dir = os.path.dirname(eve_json)
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            current_app.logger.info(f"已创建输出目录: {output_dir}")
        except Exception as e:
            current_app.logger.error(f"无法创建输出目录: {str(e)}")
            return False, f"无法创建输出目录: {str(e)}", None
            
    # 确保输出目录有写入权限
    if not os.access(output_dir, os.W_OK):
        try:
            os.chmod(output_dir, 0o755)
            current_app.logger.info(f"已设置输出目录权限: {output_dir}")
        except Exception as e:
            current_app.logger.error(f"无法设置输出目录权限: {str(e)}")
            return False, f"无法设置输出目录权限: {str(e)}", None
    
    # 应急模式 - 当其他所有模式都失败时使用
    if mode == "emergency":
        current_app.logger.warning(f"使用应急模式（tcpdump）处理PCAP文件: {pcap_file}")
        try:
            # 使用tcpdump生成简单的JSON摘要
            emergency_json = eve_json.replace('.json', '_emergency.json')
            
            # 检查tcpdump版本和功能
            version_cmd = ["tcpdump", "--version"]
            process = subprocess.Popen(version_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = process.communicate()
            version_info = stdout.decode('utf-8')
            current_app.logger.info(f"tcpdump版本: {version_info}")
            
            # 使用tcpdump提取PCAP文件的基本信息
            tcpdump_cmd = [
                "tcpdump", 
                "-r", pcap_file,  # 读取PCAP文件 
                "-n",             # 不解析主机名
                "-v",             # 详细输出
                "-c", "1000"      # 最多处理1000个包
            ]
            current_app.logger.info(f"执行tcpdump命令: {' '.join(tcpdump_cmd)}")
            
            process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # 检查tcpdump是否成功
            if process.returncode != 0:
                stderr_text = stderr.decode('utf-8')
                current_app.logger.error(f"tcpdump分析失败: {stderr_text}")
                return False, f"tcpdump分析失败: {stderr_text}", None
                
            # 解析tcpdump输出
            stdout_text = stdout.decode('utf-8')
            stderr_text = stderr.decode('utf-8')
            
            # 通过tcpdump输出创建简化的JSON
            packet_data = []
            lines = stdout_text.split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                    
                # 匹配IP地址
                src_ip = None
                dst_ip = None
                ip_match = re.findall(r'(\d+\.\d+\.\d+\.\d+)\.?(\d+)? > (\d+\.\d+\.\d+\.\d+)\.?(\d+)?:', line)
                
                if ip_match:
                    src_ip = ip_match[0][0]
                    src_port = ip_match[0][1] if ip_match[0][1] else None
                    dst_ip = ip_match[0][2]
                    dst_port = ip_match[0][3] if ip_match[0][3] else None
                    
                    packet = {
                        "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'),
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "proto": "unknown"
                    }
                    
                    if src_port:
                        packet["src_port"] = int(src_port)
                    if dst_port:
                        packet["dest_port"] = int(dst_port)
                        
                    # 识别协议
                    if "ICMP" in line:
                        packet["proto"] = "ICMP"
                    elif "TCP" in line:
                        packet["proto"] = "TCP"
                    elif "UDP" in line:
                        packet["proto"] = "UDP"
                        
                    # 识别可能的威胁特征
                    if "Flags [S]" in line:  # SYN扫描
                        packet["alert"] = {
                            "signature": "可能的端口扫描",
                            "category": "网络扫描",
                            "severity": 2
                        }
                    elif "Flags [FPU]" in line:  # FIN-PSH-URG扫描
                        packet["alert"] = {
                            "signature": "可能的FIN-PSH-URG扫描",
                            "category": "网络扫描",
                            "severity": 2
                        }
                    elif "ICMP echo request" in line:  # Ping扫描
                        packet["alert"] = {
                            "signature": "ICMP回显请求 (Ping)",
                            "category": "网络扫描",
                            "severity": 1
                        }
                    elif "bad-len" in line or "malformed" in line:  # 畸形包
                        packet["alert"] = {
                            "signature": "畸形数据包",
                            "category": "异常流量",
                            "severity": 3
                        }
                        
                    packet_data.append(packet)
            
            # 写入紧急模式JSON文件
            if packet_data:
                with open(emergency_json, 'w') as f:
                    for packet in packet_data:
                        f.write(json.dumps(packet) + "\n")
                        
                current_app.logger.info(f"使用tcpdump生成了紧急模式分析结果: {emergency_json}")
                return True, None, emergency_json
            else:
                current_app.logger.warning("tcpdump未提取到任何数据包信息")
                return False, "tcpdump未提取到任何数据包信息", None
                
        except Exception as e:
            current_app.logger.error(f"应急模式处理失败: {str(e)}", exc_info=True)
            return False, f"应急模式处理失败: {str(e)}", None
    else:
        # 根据模式设置Suricata命令参数
        if mode == "default":
            # 默认模式 - 使用简单参数，与成功的手动命令类似
            cmd = [
                current_app.config['SURICATA_BIN'],
                '-c', current_app.config['SURICATA_CONFIG'],
                '-r', pcap_file,
                '-v',  # 添加详细输出
                '-k', 'none',  # 忽略校验和错误
            ]
            
            # 如果要输出到非默认位置，添加输出参数
            if not eve_json.startswith('/var/log/suricata/'):
                cmd.extend(['--set', f'outputs.eve-log.filename={eve_json}'])
        elif mode == "safe":
            # 安全模式，使用最少的必需参数
            cmd = [
                current_app.config['SURICATA_BIN'],
                '-c', current_app.config['SURICATA_CONFIG'],
                '--runmode=single',  # 使用单线程模式
                '-k', 'none',  # 忽略校验和错误
                '-r', pcap_file,
                '-v',  # 详细输出
            ]
            
            # 如果要输出到非默认位置，添加输出参数
            if not eve_json.startswith('/var/log/suricata/'):
                cmd.extend(['--set', f'outputs.eve-log.filename={eve_json}'])
        elif mode == "minimal":
            # 最小规则集模式
            cmd = [
                current_app.config['SURICATA_BIN'],
                '--disable-detection',  # 禁用规则检测
                '-k', 'none',  # 忽略校验和错误
                '-c', current_app.config['SURICATA_CONFIG'],
                '-r', pcap_file,
                '-v',  # 详细输出
            ]
            
            # 如果要输出到非默认位置，添加输出参数
            if not eve_json.startswith('/var/log/suricata/'):
                cmd.extend(['--set', f'outputs.eve-log.filename={eve_json}'])
        else:
            return False, "未知的分析模式", None
        
        current_app.logger.info(f"执行Suricata命令({mode}模式): {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            stdout_text = stdout.decode('utf-8')
            stderr_text = stderr.decode('utf-8')
            
            if stdout_text:
                current_app.logger.info(f"Suricata输出: {stdout_text}")
            
            if process.returncode != 0:
                current_app.logger.error(f"Suricata分析失败 (返回码 {process.returncode}): {stderr_text}")
                
                # 检查是否是不支持的数据链路类型
                if "datalink type" in stderr_text and "not (yet) supported" in stderr_text:
                    return False, "PCAP文件格式不被Suricata支持，请使用标准的以太网捕获格式", None
                
                # 检查是否是段错误
                if process.returncode < 0 or process.returncode == 139 or process.returncode == 11 or process.returncode == -11:
                    current_app.logger.error(f"Suricata可能遇到了段错误或内存访问问题，返回码: {process.returncode}")
                    # 尝试使用 file 命令检查文件格式
                    try:
                        file_cmd = ["file", pcap_file]
                        file_process = subprocess.Popen(file_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        file_stdout, _ = file_process.communicate()
                        file_output = file_stdout.decode('utf-8')
                        current_app.logger.info(f"PCAP文件格式: {file_output}")
                    except Exception as e:
                        current_app.logger.error(f"检查文件格式失败: {str(e)}")
                    
                    # 尝试使用 tcpdump 检查包数量
                    try:
                        tcpdump_cmd = ["tcpdump", "-r", pcap_file, "-c", "1", "-nn"]
                        tcpdump_process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        _, tcpdump_stderr = tcpdump_process.communicate()
                        tcpdump_output = tcpdump_stderr.decode('utf-8')
                        current_app.logger.info(f"tcpdump检查结果: {tcpdump_output}")
                    except Exception as e:
                        current_app.logger.error(f"使用tcpdump检查文件失败: {str(e)}")
                        
                    return False, "Suricata处理此PCAP文件时崩溃 (返回码: {})，可能包含特殊的数据包结构".format(process.returncode), None
                
                # 检查是否是文件不存在
                if "No such file or directory" in stderr_text:
                    current_app.logger.error(f"Suricata找不到文件: {pcap_file}")
                    current_app.logger.info(f"文件存在检查: {os.path.exists(pcap_file)}")
                    if os.path.exists(pcap_file):
                        current_app.logger.info(f"文件权限: {oct(os.stat(pcap_file).st_mode)}")
                    return False, f"Suricata找不到PCAP文件: {stderr_text}", None
                
                return False, f"Suricata分析失败: {stderr_text}", None
            
            # 检查eve.json是否生成
            if not os.path.exists(eve_json):
                # 如果指定位置不存在，检查默认位置
                default_eve = '/var/log/suricata/eve.json'
                if os.path.exists(default_eve):
                    try:
                        # 复制默认位置的文件到指定位置
                        current_app.logger.info(f"从默认位置 {default_eve} 复制结果到 {eve_json}")
                        shutil.copy2(default_eve, eve_json)
                        
                        # 确保复制成功
                        if os.path.exists(eve_json):
                            current_app.logger.info(f"成功从系统默认位置复制结果文件")
                        else:
                            error_msg = "复制分析结果文件失败"
                            current_app.logger.error(error_msg)
                            return False, error_msg, None
                    except Exception as e:
                        error_msg = f"复制分析结果文件失败: {str(e)}"
                        current_app.logger.error(error_msg)
                        return False, error_msg, None
                else:
                    error_msg = "分析结果文件不存在（默认位置和指定位置都未找到）"
                    current_app.logger.error(error_msg)
                    return False, error_msg, None
            
            if os.path.getsize(eve_json) == 0:
                error_msg = "分析结果为空，可能是PCAP文件内容不兼容或没有匹配的规则"
                current_app.logger.warning(error_msg)
                return False, error_msg, None
            
            current_app.logger.info(f"Suricata分析成功，结果保存在: {eve_json}")
            return True, None, eve_json
        except Exception as e:
            current_app.logger.error(f"执行Suricata命令失败: {str(e)}")
            return False, f"执行Suricata命令失败: {str(e)}", None

def process_alerts_from_eve(eve_json, pcap_filename):
    """从eve.json中处理告警并存储到数据库"""
    alerts = []
    
    if not os.path.exists(eve_json):
        # 尝试使用默认文件
        default_eve = '/var/log/suricata/eve.json'
        if os.path.exists(default_eve):
            current_app.logger.info(f"使用默认位置的eve.json: {default_eve}")
            eve_json = default_eve
        else:
            current_app.logger.error(f"Eve.json文件不存在: {eve_json} 和默认位置 {default_eve} 都不存在")
            return [], "Eve.json文件不存在"
    
    # 日志处理前的文件信息
    file_size = os.path.getsize(eve_json)
    current_app.logger.info(f"处理eve.json文件: {eve_json}, 大小: {file_size} 字节")
    
    # 检查文件是否为空
    if file_size == 0:
        current_app.logger.warning(f"Eve.json文件为空")
        return [], "Eve.json文件为空，未检测到告警"
        
    try:
        alert_count = 0
        line_count = 0
        
        # 先读取文件内容并打印前几行用于调试
        debug_lines = []
        try:
            with open(eve_json, 'r') as f:
                for i, line in enumerate(f):
                    if i < 10:  # 只读取前10行用于调试
                        debug_lines.append(line.strip())
                    else:
                        break
            
            if debug_lines:
                current_app.logger.info(f"Eve.json前几行内容:")
                for i, line in enumerate(debug_lines):
                    current_app.logger.info(f"行 {i+1}: {line[:500]}...")
            else:
                current_app.logger.warning("无法读取Eve.json内容用于调试")
        except Exception as e:
            current_app.logger.warning(f"读取Eve.json调试内容失败: {str(e)}")
        
        with open(eve_json, 'r') as f:
            for line in f:
                line_count += 1
                
                try:
                    log_entry = json.loads(line)
                    
                    # 记录每个事件的类型
                    event_type = log_entry.get('event_type', 'unknown')
                    
                    # 只处理告警事件
                    if 'alert' in log_entry:
                        alert_count += 1
                        # 创建告警记录
                        alert = Alert()
                        
                        # 记录告警详情
                        alert_details = {
                            'event_type': event_type,
                            'timestamp': log_entry.get('timestamp'),
                            'alert': log_entry.get('alert', {})
                        }
                        current_app.logger.info(f"发现告警 #{alert_count}: {json.dumps(alert_details)[:500]}...")
                        
                        # 设置基本属性
                        if 'timestamp' in log_entry:
                            try:
                                alert.timestamp = datetime.strptime(
                                    log_entry['timestamp'].split('+')[0], 
                                    '%Y-%m-%dT%H:%M:%S.%f'
                                )
                            except Exception as e:
                                current_app.logger.warning(f"解析时间戳失败: {str(e)}")
                                alert.timestamp = datetime.now()
                        
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
                        
                        # 设置载荷信息
                        if 'payload' in log_entry:
                            alert.payload = log_entry['payload']
                        elif 'payload_printable' in log_entry:
                            alert.payload = log_entry['payload_printable']
                        
                        # 设置PCAP文件名
                        alert.pcap_filename = pcap_filename
                        
                        # 保存到数据库
                        db.session.add(alert)
                        alerts.append(alert)
                    elif line_count <= 50 or line_count % 100 == 0:  # 控制日志输出频率
                        # 记录非告警事件类型
                        current_app.logger.debug(f"第{line_count}行: 事件类型 '{event_type}' (非告警)")
                        
                except json.JSONDecodeError as json_err:
                    # 忽略非JSON行
                    current_app.logger.warning(f"第{line_count}行不是有效的JSON: {str(json_err)}")
                    if line_count <= 10:  # 只显示前10行的详细错误
                        current_app.logger.warning(f"内容: {line[:200]}...")
                    continue
                except Exception as e:
                    current_app.logger.error(f"处理告警行失败: {str(e)}")
                    continue
            
            # 提交所有告警
            if alerts:
                db.session.commit()
                current_app.logger.info(f"处理了{line_count}行，发现{alert_count}个告警，保存了{len(alerts)}个告警记录")
            else:
                current_app.logger.warning(f"处理了{line_count}行，发现{alert_count}个告警，但没有保存任何告警记录")
                
                # 如果没有告警，检查是否有问题
                if line_count > 0 and alert_count == 0:
                    current_app.logger.warning("未发现告警，可能是没有匹配的规则或PCAP文件内容没有触发告警")
                elif line_count == 0:
                    current_app.logger.warning("Eve.json文件内容为空或格式不正确")
            
        return alerts, None
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"处理告警失败: {str(e)}", exc_info=True)
        return [], f"处理告警失败: {str(e)}"

@pcap_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_pcap():
    """上传PCAP文件并进行分析"""
    try:
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
        
        # 获取并确保上传目录存在（使用绝对路径）
        upload_folder = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
        current_app.logger.info(f"上传目录: {upload_folder}")
        
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder, exist_ok=True)
            current_app.logger.info(f"已创建上传目录: {upload_folder}")
        
        # 生成唯一ID和文件名
        unique_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        unique_filename = f"{unique_id}_{filename}"
        file_path = os.path.join(upload_folder, unique_filename)
        
        # 保存文件
        current_app.logger.info(f"保存PCAP文件: {file_path}")
        file.save(file_path)
        
        # 检查文件是否成功保存
        if not os.path.exists(file_path):
            current_app.logger.error(f"文件保存失败: {file_path}")
            return jsonify({'message': '文件保存失败，请重试'}), 500
        
        # 设置正确的文件权限
        os.chmod(file_path, 0o644)
        
        # 获取文件大小
        file_size = os.path.getsize(file_path)
        current_app.logger.info(f"PCAP文件已保存: {file_path}, 大小: {file_size} 字节")
        
        # 先创建PCAP文件记录
        pcap_record = PcapFile(
            filename=unique_filename,
            original_filename=filename,
            file_size=file_size,
            upload_time=datetime.now(),
            processed=False,
            alert_count=0
        )
        
        # 保存记录到数据库
        db.session.add(pcap_record)
        db.session.commit()
        current_app.logger.info(f"已创建PCAP文件记录: ID={pcap_record.id}, 文件名={unique_filename}")
        
        # 验证文件内容
        if not validate_pcap_content(file_path):
            os.remove(file_path)
            return jsonify({'message': '文件内容不是有效的PCAP格式'}), 400
        
        # 创建分析输出目录 - 使用uploads目录，不创建额外的temp子目录
        output_dir = upload_folder
        eve_json = os.path.join(output_dir, f"{unique_id}_eve.json")
        
        current_app.logger.info(f"开始分析PCAP文件: {file_path}, 输出目录: {output_dir}")
        
        # 确保文件不会被其他进程更改或删除
        shutil.copy2(file_path, file_path + ".bak")
        current_app.logger.info(f"已创建PCAP文件备份: {file_path}.bak")
        
        # 使用Suricata分析PCAP
        eve_json, error = analyze_pcap_with_suricata(file_path, output_dir, eve_filename=f"{unique_id}_eve.json")
        
        # 如果原始文件被删除，尝试从备份恢复
        if error and "文件不存在" in error and os.path.exists(file_path + ".bak"):
            current_app.logger.warning(f"原始文件丢失，尝试从备份恢复: {file_path}.bak")
            shutil.copy2(file_path + ".bak", file_path)
            # 重试分析
            eve_json, error = analyze_pcap_with_suricata(file_path, output_dir, eve_filename=f"{unique_id}_eve.json")
        
        if error:
            # 即使分析失败，也标记为已处理
            pcap_record.processed = True
            db.session.commit()
            current_app.logger.error(f"Suricata分析失败: {error}")
            return jsonify({'message': error}), 500
        
        # 处理告警
        alerts, error = process_alerts_from_eve(eve_json, unique_filename)
        
        # 更新PCAP记录的处理状态和告警数量
        pcap_record.processed = True
        pcap_record.alert_count = len(alerts)
        db.session.commit()
        current_app.logger.info(f"已更新PCAP文件记录: ID={pcap_record.id}, 告警数={pcap_record.alert_count}")
        
        if error:
            current_app.logger.error(f"处理告警失败: {error}")
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
        
        # 清理分析生成的临时文件
        try:
            # 保留eve.json文件用于调试
            # if os.path.exists(eve_json):
            #     os.remove(eve_json)
            #     current_app.logger.info(f"已删除临时分析结果文件: {eve_json}")
            current_app.logger.info(f"保留eve.json文件用于分析调试: {eve_json}")
                
            # 清理备份文件
            if os.path.exists(file_path + ".bak"):
                os.remove(file_path + ".bak")
                current_app.logger.info(f"已删除PCAP文件备份: {file_path}.bak")
        except Exception as e:
            current_app.logger.warning(f"清理临时文件失败: {str(e)}")
        
        return jsonify({
            'message': '文件上传并分析成功',
            'filename': unique_filename,
            'alert_count': alert_count,
            'top_threats': top_threats_list
        }), 200
    except Exception as e:
        current_app.logger.error(f"处理PCAP文件时出错: {str(e)}", exc_info=True)
        
        # 清理可能的残留文件
        try:
            upload_folder = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
            unique_id = str(uuid.uuid4())  # 这可能不是原始的unique_id，但我们只是为了安全检查临时文件
            
            # 检查并清理可能的临时文件
            temp_patterns = [
                os.path.join(upload_folder, f"{unique_id}_*.pcap"),
                os.path.join(upload_folder, f"{unique_id}_*.bak"),
                os.path.join(upload_folder, f"{unique_id}_eve.json")
            ]
            
            for pattern in temp_patterns:
                import glob
                for file_to_remove in glob.glob(pattern):
                    if os.path.exists(file_to_remove):
                        os.remove(file_to_remove)
                        current_app.logger.info(f"已清理临时文件: {file_to_remove}")
        except Exception as cleanup_error:
            current_app.logger.warning(f"清理临时文件时出错: {str(cleanup_error)}")
            
        return jsonify({'message': f'处理PCAP文件时出错: {str(e)}'}), 500

@pcap_bp.route('/list', methods=['GET'])
@jwt_required()
def list_pcap_files():
    """获取上传的PCAP文件列表"""
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    try:
        # 直接从PcapFile表查询
        pagination = PcapFile.query.order_by(
            PcapFile.upload_time.desc()
        ).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        result = [{
            'filename': item.filename,
            'original_filename': item.original_filename,
            'alert_count': item.alert_count,
            'upload_time': item.upload_time.isoformat() if item.upload_time else None,
            'file_size': item.file_size
        } for item in pagination.items]
        
        return jsonify({
            'pcap_files': result,
            'total': pagination.total,
            'pages': pagination.pages,
            'page': page,
            'per_page': per_page
        }), 200
    except Exception as e:
        current_app.logger.error(f"获取PCAP文件列表失败: {str(e)}", exc_info=True)
        return jsonify({'message': f'获取PCAP文件列表失败: {str(e)}'}), 500

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
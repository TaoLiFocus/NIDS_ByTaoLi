import subprocess
import os
import logging
import shutil
from flask import current_app

logger = logging.getLogger('app.pcap')

def check_pcap_format(pcap_file):
    """
    检查PCAP文件是否适合Suricata处理
    
    参数:
        pcap_file: PCAP文件路径
    
    返回:
        (bool, str): 包含是否适合的布尔值和错误消息（如果有）
    """
    # 确保使用绝对路径
    pcap_file = os.path.abspath(pcap_file)
    logger.info(f"检查PCAP文件格式: {pcap_file}")
    
    # 首先检查文件是否存在
    if not os.path.exists(pcap_file):
        logger.error(f"PCAP文件不存在: {pcap_file}")
        # 检查文件权限问题
        directory = os.path.dirname(pcap_file)
        if not os.path.exists(directory):
            logger.error(f"目录不存在: {directory}")
            return False, f"目录不存在: {directory}"
        elif not os.access(directory, os.R_OK):
            logger.error(f"目录无读取权限: {directory}")
            return False, f"目录无读取权限: {directory}"
            
        # 记录目录内容以便调试
        try:
            logger.info(f"目录 {directory} 内容:")
            for item in os.listdir(directory):
                logger.info(f"  - {item}")
        except Exception as e:
            logger.error(f"无法列出目录内容: {str(e)}")
            
        return False, f"文件不存在: {pcap_file}"
        
    try:
        # 检查文件大小
        file_size = os.path.getsize(pcap_file)
        if file_size == 0:
            logger.error(f"PCAP文件为空: {pcap_file}")
            return False, f"PCAP文件为空: {pcap_file}"
        logger.info(f"PCAP文件大小: {file_size} 字节")
        
        # 检查文件权限
        if not os.access(pcap_file, os.R_OK):
            logger.error(f"PCAP文件无读取权限: {pcap_file}")
            return False, f"PCAP文件无读取权限: {pcap_file}"
        
        # 创建文件备份，防止下面的检查命令意外删除文件
        backup_file = pcap_file + ".bak"
        try:
            # 创建备份前检查是否已有备份
            if not os.path.exists(backup_file):
                shutil.copy2(pcap_file, backup_file)
                logger.info(f"已创建PCAP文件备份: {backup_file}")
        except Exception as e:
            logger.warning(f"创建备份文件失败: {str(e)}")
        
        # 使用tcpdump检查PCAP文件格式
        check_cmd = ["tcpdump", "-r", pcap_file, "-c", "1", "-nn"]
        logger.info(f"执行命令: {' '.join(check_cmd)}")
        
        process = subprocess.Popen(
            check_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        stdout_text = stdout.decode('utf-8')
        stderr_text = stderr.decode('utf-8')
        
        if stdout_text:
            logger.info(f"tcpdump stdout: {stdout_text}")
        if stderr_text:
            logger.info(f"tcpdump stderr: {stderr_text}")
        
        # 检查是否有错误输出
        if process.returncode != 0:
            if "unknown data link type" in stderr_text or "not supported" in stderr_text:
                logger.error(f"PCAP文件格式不被支持: {stderr_text}")
                return False, "PCAP文件格式不被支持，请使用标准的以太网或WiFi捕获格式"
            logger.error(f"PCAP格式检查失败: {stderr_text}")
            return False, f"PCAP格式检查失败: {stderr_text}"
            
        # 检查文件是否仍然存在，可能被tcpdump修改或删除
        if not os.path.exists(pcap_file):
            logger.warning(f"tcpdump检查后文件不存在，尝试从备份恢复")
            if os.path.exists(backup_file):
                try:
                    shutil.copy2(backup_file, pcap_file)
                    logger.info(f"已从备份恢复文件: {pcap_file}")
                except Exception as e:
                    logger.error(f"恢复文件失败: {str(e)}")
                    return False, f"恢复文件失败: {str(e)}"
        
        # 使用Suricata进行额外验证 - 注意：不使用--pcap-file-delete参数！
        test_cmd = [
            current_app.config['SURICATA_BIN'],
            "--pcap-file-continuous",
            # 不使用--pcap-file-delete参数，防止文件被删除
            "-r", pcap_file,
            "-v"
        ]
        
        logger.info(f"执行命令: {' '.join(test_cmd)}")
        
        process = subprocess.Popen(
            test_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        stdout_text = stdout.decode('utf-8')
        stderr_text = stderr.decode('utf-8')
        
        if stdout_text:
            logger.info(f"suricata stdout: {stdout_text}")
        if stderr_text:
            logger.info(f"suricata stderr: {stderr_text}")
        
        # 检查是否有Suricata不支持的错误
        if "datalink type" in stderr_text and "not (yet) supported" in stderr_text:
            logger.error(f"Suricata不支持的数据链路类型: {stderr_text}")
            return False, "PCAP文件包含Suricata不支持的数据链路类型，请使用标准的以太网捕获格式"
        
        # 再次检查文件是否存在（可能被Suricata命令删除）
        if not os.path.exists(pcap_file):
            logger.warning(f"Suricata检查后文件不存在，尝试从备份恢复")
            if os.path.exists(backup_file):
                try:
                    shutil.copy2(backup_file, pcap_file)
                    logger.info(f"已从备份恢复文件: {pcap_file}")
                except Exception as e:
                    logger.error(f"恢复文件失败: {str(e)}")
                    return False, f"恢复文件失败: {str(e)}"
            
        return True, None
        
    except Exception as e:
        logger.error(f"检查PCAP文件格式失败: {str(e)}")
        return False, f"检查PCAP文件格式失败: {str(e)}"

def convert_pcap_format(input_file, output_file):
    """
    尝试将不兼容的PCAP文件转换为Suricata可以处理的格式
    注意: 此功能可能不适用于所有类型的PCAP文件
    
    参数:
        input_file: 输入PCAP文件路径
        output_file: 输出PCAP文件路径
    
    返回:
        (bool, str): 转换是否成功的布尔值和错误消息（如果有）
    """
    # 确保使用绝对路径
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)
    
    logger.info(f"尝试转换PCAP文件: {input_file} -> {output_file}")
    
    # 详细检查输入文件
    if not os.path.exists(input_file):
        error_msg = f"输入文件不存在: {input_file}"
        logger.error(error_msg)
        
        # 首先检查是否有备份文件可以恢复
        backup_file = input_file + ".bak"
        if os.path.exists(backup_file):
            logger.info(f"发现备份文件: {backup_file}，尝试恢复")
            try:
                shutil.copy2(backup_file, input_file)
                logger.info(f"已从备份文件恢复: {input_file}")
                # 重新检查文件是否存在
                if os.path.exists(input_file):
                    logger.info(f"文件恢复成功，继续处理: {input_file}")
                else:
                    logger.error(f"恢复后文件仍不存在: {input_file}")
                    return False, error_msg
            except Exception as e:
                logger.error(f"从备份恢复文件失败: {str(e)}")
                return False, f"{error_msg} (恢复尝试失败: {str(e)})"
        else:
            # 列出上传目录中的文件，帮助诊断问题
            try:
                upload_dir = os.path.dirname(input_file)
                logger.info(f"列出 {upload_dir} 目录中的文件:")
                if os.path.exists(upload_dir):
                    files = os.listdir(upload_dir)
                    for file in files:
                        logger.info(f"  - {file}")
                    logger.info(f"目录中共有 {len(files)} 个文件")
                else:
                    logger.error(f"上传目录不存在: {upload_dir}")
            except Exception as e:
                logger.error(f"列出目录内容时出错: {str(e)}")
                
            return False, error_msg
    
    # 检查输入文件是否可读
    if not os.access(input_file, os.R_OK):
        error_msg = f"输入文件无法读取，可能是权限问题: {input_file}"
        logger.error(error_msg)
        return False, error_msg
    
    # 检查输入文件大小
    file_size = os.path.getsize(input_file)
    if file_size == 0:
        error_msg = f"输入文件大小为0字节: {input_file}"
        logger.error(error_msg)
        return False, error_msg
    logger.info(f"输入文件大小: {file_size} 字节")
        
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"已创建输出目录: {output_dir}")
        except Exception as e:
            error_msg = f"无法创建输出目录: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    try:
        # 直接使用tcpdump转换，简化转换逻辑
        logger.info(f"使用tcpdump转换格式: {input_file}")
        tcpdump_cmd = [
            "tcpdump", 
            "-r", input_file,  # 读取输入文件
            "-w", output_file,  # 写入输出文件
            "-s", "0"  # 捕获完整包
        ]
        
        logger.info(f"执行tcpdump转换命令: {' '.join(tcpdump_cmd)}")
        
        process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            stderr_text = stderr.decode('utf-8')
            logger.error(f"tcpdump格式转换失败: {stderr_text}")
            return False, f"PCAP格式转换失败: {stderr_text}"
        
        # 检查输出文件是否存在且大小不为0
        if not os.path.exists(output_file):
            error_msg = f"转换后的文件不存在: {output_file}"
            logger.error(error_msg)
            return False, error_msg
            
        if os.path.getsize(output_file) == 0:
            error_msg = "转换后的文件为空"
            logger.error(error_msg)
            return False, error_msg
            
        # 使用更强的转换方法 - 尝试使用editcap工具（来自wireshark套件）
        # 如果不存在，回退到使用tcprewrite（来自tcpreplay套件）
        strong_convert_success = False
        
        # 首先尝试editcap（如果可用）
        try:
            editcap_cmd = ["editcap", "-T", "ether", output_file, output_file + ".ether"]
            logger.info(f"尝试使用editcap转换为以太网格式: {' '.join(editcap_cmd)}")
            
            process = subprocess.Popen(
                editcap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and os.path.exists(output_file + ".ether"):
                # 成功转换
                shutil.move(output_file + ".ether", output_file)
                logger.info(f"使用editcap成功转换为以太网格式")
                strong_convert_success = True
            else:
                stderr_text = stderr.decode('utf-8')
                logger.warning(f"editcap转换失败，将尝试其他方法: {stderr_text}")
        except FileNotFoundError:
            logger.warning("editcap工具不可用，将尝试其他转换方法")
        except Exception as e:
            logger.warning(f"使用editcap转换时出错: {str(e)}")
            
        # 如果editcap失败，尝试tcprewrite
        if not strong_convert_success:
            try:
                tcprewrite_cmd = [
                    "tcprewrite", 
                    "--dlt=enet", 
                    "--infile=" + output_file, 
                    "--outfile=" + output_file + ".ether"
                ]
                logger.info(f"尝试使用tcprewrite转换为以太网格式: {' '.join(tcprewrite_cmd)}")
                
                process = subprocess.Popen(
                    tcprewrite_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = process.communicate()
                
                if process.returncode == 0 and os.path.exists(output_file + ".ether"):
                    # 成功转换
                    shutil.move(output_file + ".ether", output_file)
                    logger.info(f"使用tcprewrite成功转换为以太网格式")
                    strong_convert_success = True
                else:
                    stderr_text = stderr.decode('utf-8')
                    logger.warning(f"tcprewrite转换失败: {stderr_text}")
            except FileNotFoundError:
                logger.warning("tcprewrite工具不可用，转换可能不完整")
            except Exception as e:
                logger.warning(f"使用tcprewrite转换时出错: {str(e)}")
        
        # 设置正确的权限
        os.chmod(output_file, 0o644)
        logger.info(f"PCAP文件转换成功: {output_file}, 大小: {os.path.getsize(output_file)} 字节")
        
        # 最后检查文件类型
        try:
            file_check_cmd = ["file", output_file]
            process = subprocess.Popen(
                file_check_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            stdout_text = stdout.decode('utf-8')
            logger.info(f"转换后文件类型: {stdout_text}")
            
            # 如果输出中包含 "802.11"，警告转换可能不完整
            if "802.11" in stdout_text:
                logger.warning("转换后文件仍包含802.11格式，Suricata可能无法处理")
        except Exception as e:
            logger.warning(f"检查文件类型时出错: {str(e)}")
            
        return True, None
        
    except Exception as e:
        error_msg = f"转换PCAP文件格式失败: {str(e)}"
        logger.error(error_msg)
        return False, error_msg 
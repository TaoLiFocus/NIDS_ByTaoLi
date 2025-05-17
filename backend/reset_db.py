#!/usr/bin/env python3
"""
数据库重置脚本 - 清理数据库并创建默认管理员用户
"""
import os
import sys
from flask import Flask
from sqlalchemy import text
from app import create_app
from app.database import db
from app.models.user import User
from app.models.alert import Alert
from app.models.pcap import PcapFile
from datetime import datetime, timedelta
import random
import sqlite3
import mysql.connector
from dotenv import load_dotenv

def reset_database():
    """重置数据库并创建默认管理员账户"""
    print("开始重置数据库...")
    
    # 创建应用实例
    app = create_app('development')
    
    # 在应用上下文中操作
    with app.app_context():
        try:
            # 手动按顺序删除表（先删除有外键引用的表）
            print("正在删除数据库表（按外键依赖顺序）...")
            
            # 使用事务执行SQL
            with db.engine.begin() as connection:
                # 禁用外键检查
                connection.execute(text("SET FOREIGN_KEY_CHECKS=0;"))
                
                # 删除所有表
                tables = ["alerts", "pcap_files", "monitor_sessions", "suricata_settings", "system_settings", "users"]
                for table in tables:
                    try:
                        print(f"删除表 {table}...")
                        connection.execute(text(f"DROP TABLE IF EXISTS {table};"))
                    except Exception as e:
                        print(f"删除表 {table} 时出错: {e}")
                
                # 重新启用外键检查
                connection.execute(text("SET FOREIGN_KEY_CHECKS=1;"))
            
            # 创建所有表
            print("创建新表结构...")
            db.create_all()
            
            # 创建默认管理员账户
            print("创建默认管理员账户...")
            admin = User(
                username='admin',
                email='admin@example.com',
                password='admin123',
                role='admin'
            )
            
            # 添加到数据库
            db.session.add(admin)
            
            # 添加测试PCAP文件数据
            print("添加测试PCAP文件数据...")
            
            test_pcaps = [
                ("01234567-1234-5678-9abc-123456789abc_sample1.pcap", "sample1.pcap", 1024 * 1024, 5),
                ("12345678-1234-5678-9abc-123456789abc_sample2.pcap", "sample2.pcap", 2048 * 1024, 0),
                ("23456789-1234-5678-9abc-123456789abc_malicious.pcap", "malicious.pcap", 512 * 1024, 8)
            ]
            
            for i, (filename, original_name, size, alert_count) in enumerate(test_pcaps):
                upload_time = datetime.now() - timedelta(days=i)
                pcap_file = PcapFile(
                    filename=filename,
                    original_filename=original_name,
                    file_size=size,
                    upload_time=upload_time,
                    processed=True,
                    alert_count=alert_count
                )
                db.session.add(pcap_file)
            
            # 添加测试告警数据
            print("添加测试告警数据...")
            
            # 为测试PCAP文件添加告警
            categories = ["Potential Corporate Privacy Violation", "Attempted Information Leak", 
                        "Web Application Attack", "A Network Trojan was Detected", 
                        "Potentially Bad Traffic", "Attempted Denial of Service"]
            
            signatures = ["ET POLICY PE EXE or DLL Windows file download", 
                        "ET MALWARE Suspicious User-Agent (suspicious UA)", 
                        "ET WEB_SERVER SQL Injection Attempt", 
                        "ET SCAN NMAP OS Detection Probe", 
                        "ET TROJAN Metasploit Meterpreter Reverse HTTPS Tunnel"]
            
            severities = [1, 2, 3]  # 低、中、高
            
            # 生成一些随机IP
            ips = [f"192.168.1.{i}" for i in range(1, 10)]
            external_ips = [f"203.0.113.{i}" for i in range(1, 10)]
            
            # 生成随机端口
            ports = [80, 443, 22, 21, 25, 53, 3306, 5432]
            
            # 生成随机协议
            protocols = ["TCP", "UDP", "ICMP"]
            
            # 生成随机应用协议
            app_protocols = ["HTTP", "HTTPS", "SSH", "FTP", "DNS", "TLS", "MySQL", None]
            
            # 添加测试告警数据
            for pcap in test_pcaps:
                # 跳过无告警的PCAP
                if pcap[3] == 0:
                    continue
                    
                for i in range(pcap[3]):
                    timestamp = datetime.now() - timedelta(days=random.randint(0, 5), 
                                                        hours=random.randint(0, 23), 
                                                        minutes=random.randint(0, 59))
                    alert = Alert(
                        timestamp=timestamp,
                        alert_action="alert",
                        alert_gid=random.randint(1, 3),
                        alert_signature_id=random.randint(2000000, 3000000),
                        alert_rev=random.randint(1, 10),
                        alert_signature=random.choice(signatures),
                        alert_category=random.choice(categories),
                        alert_severity=random.choice(severities),
                        src_ip=random.choice(ips),
                        dest_ip=random.choice(external_ips),
                        src_port=random.choice(ports),
                        dest_port=random.choice(ports),
                        proto=random.choice(protocols),
                        app_proto=random.choice(app_protocols),
                        pcap_filename=pcap[0]
                    )
                    db.session.add(alert)
            
            db.session.commit()
            
            print(f"默认管理员用户创建成功:")
            print(f"  用户名: admin")
            print(f"  密码: admin123")
            print(f"  角色: admin")
            print(f"已添加测试数据: {len(test_pcaps)}个PCAP文件和对应告警")
        
        except Exception as e:
            print(f"重置数据库时出错: {e}")
            db.session.rollback()
            raise
    
    print("数据库重置完成!")

if __name__ == "__main__":
    reset_database() 
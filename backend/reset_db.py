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
                tables = ["pcap_files", "monitor_sessions", "suricata_settings", "system_settings", "users"]
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
            db.session.commit()
            
            print(f"默认管理员用户创建成功:")
            print(f"  用户名: admin")
            print(f"  密码: admin123")
            print(f"  角色: admin")
        
        except Exception as e:
            print(f"重置数据库时出错: {e}")
            db.session.rollback()
            raise
    
    print("数据库重置完成!")

if __name__ == "__main__":
    reset_database() 
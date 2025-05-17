from datetime import datetime
from ..database import db

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # alert信息
    alert_action = db.Column(db.String(20))
    alert_gid = db.Column(db.Integer)
    alert_signature_id = db.Column(db.Integer)
    alert_rev = db.Column(db.Integer)
    alert_signature = db.Column(db.String(255))
    alert_category = db.Column(db.String(255))
    alert_severity = db.Column(db.Integer)
    
    # 网络信息
    src_ip = db.Column(db.String(39), index=True)  # 支持IPv6
    dest_ip = db.Column(db.String(39), index=True) 
    src_port = db.Column(db.Integer)
    dest_port = db.Column(db.Integer)
    proto = db.Column(db.String(10))
    
    # 应用协议
    app_proto = db.Column(db.String(20))
    
    # 数据包信息
    pcap_filename = db.Column(db.String(255), nullable=True)
    
    # 告警详情
    payload = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'alert_action': self.alert_action,
            'alert_gid': self.alert_gid,
            'alert_signature_id': self.alert_signature_id,
            'alert_rev': self.alert_rev,
            'alert_signature': self.alert_signature,
            'alert_category': self.alert_category,
            'alert_severity': self.alert_severity,
            'src_ip': self.src_ip,
            'dest_ip': self.dest_ip,
            'src_port': self.src_port,
            'dest_port': self.dest_port,
            'proto': self.proto,
            'app_proto': self.app_proto,
            'pcap_filename': self.pcap_filename,
            'payload': self.payload
        }
    
    def __repr__(self):
        return f'<Alert {self.id}: {self.alert_signature}>' 
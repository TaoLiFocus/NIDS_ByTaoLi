from datetime import datetime
from ..database import db

class PcapFile(db.Model):
    """PCAP文件记录模型"""
    __tablename__ = 'pcap_files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, index=True)
    original_filename = db.Column(db.String(255))
    upload_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    file_size = db.Column(db.Integer)
    processed = db.Column(db.Boolean, default=False)
    alert_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'upload_time': self.upload_time.isoformat() if self.upload_time else None,
            'file_size': self.file_size,
            'processed': self.processed,
            'alert_count': self.alert_count
        }
    
    def __repr__(self):
        return f'<PcapFile {self.id}: {self.original_filename}>' 
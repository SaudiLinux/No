#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماسح Google Dorks المتقدم لاكتشاف الصفحات الإدارية واللوحات الخلفية
"""

import requests
import time
import re
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any
import random

class GoogleDorksScanner:
    """
    ماسح متقدم يستخدم تقنيات Google Dorks لاكتشاف:
    - صفحات تسجيل الدخول الإدارية
    - لوحات التحكم
    - الملفات الحساسة
    - الدلائل المفتوحة
    """
    
    def __init__(self, delay: float = 1.0):
        """
        تهيئة الماسح
        
        Args:
            delay: تأخير بين الطلبات (ثواني)
        """
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # قوالب Google Dorks المخصصة
        self.dorks_templates = {
            'admin_login': [
                'site:{domain} inurl:admin | administrator | adm | login | l0gin | wp-login',
                'site:{domain} intitle:"login" "admin"',
                'site:{domain} intitle:"admin login" | "administrator login"',
                'site:{domain} inurl:admin/login | administrator/login | panel/admin',
            ],
            'admin_directories': [
                'site:{domain} intitle:"index of / admin"',
                'site:{domain} intitle:"index of /" "admin"',
                'site:{domain} intitle:"index of /" "administrator"',
                'site:{domain} intitle:"index of /" "control panel"',
            ],
            'admin_files': [
                'site:{domain} inurl:admin intitle:admin intext:admin',
                'site:{domain} filetype:php inurl:admin | administrator',
                'site:{domain} filetype:asp inurl:admin | administrator',
                'site:{domain} filetype:jsp inurl:admin | administrator',
            ],
            'config_files': [
                'site:{domain} filetype:env | filetype:config | filetype:ini',
                'site:{domain} "database.php" | "config.php" | "wp-config.php"',
                'site:{domain} intitle:"index of /" "config" | "settings"',
            ],
            'backup_files': [
                'site:{domain} filetype:sql | filetype:backup | filetype:bak',
                'site:{domain} intitle:"index of /" "backup" | "backups"',
                'site:{domain} "*.sql" | "*.backup" | "*.bak"',
            ],
            'log_files': [
                'site:{domain} filetype:log | "log.txt" | "error.log"',
                'site:{domain} intitle:"index of /" "logs"',
                'site:{domain} "access.log" | "error.log" | "debug.log"',
            ],
            'open_directories': [
                'site:{domain} intitle:"index of /"',
                'site:{domain} intitle:"index of /" "parent directory"',
                'site:{domain} intitle:"index of /" "last modified"',
            ],
            'sensitive_pages': [
                'site:{domain} inurl:phpmyadmin | inurl:adminer | inurl:sql',
                'site:{domain} inurl:wp-admin | inurl:wp-login.php',
                'site:{domain} inurl:drupal/admin | inurl:joomla/administrator',
                'site:{domain} inurl:panel | inurl:dashboard | inurl:control',
            ]
        }
    
    def extract_domain(self, url: str) -> str:
        """استخراج النطاق من الرابط"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def build_dork_queries(self, domain: str) -> Dict[str, List[str]]:
        """بناء استعلامات Google Dorks للنطاق"""
        queries = {}
        
        for category, templates in self.dorks_templates.items():
            queries[category] = [template.format(domain=domain) for template in templates]
        
        return queries
    
    def search_with_dork(self, query: str, max_results: int = 10) -> List[Dict[str, str]]:
        """
        محاكاة البحث باستخدام Google Dork (لأغراض التعليمية)
        في الواقع، يجب استخدام Google Custom Search API
        """
        # هذه دالة محاكاة للبحث
        # في التطبيق الفعلي، استخدم Google Custom Search API
        
        results = []
        
        # محاكاة نتائج البحث بناءً على نوع الاستعلام
        if 'admin' in query.lower() and 'login' in query.lower():
            # محاكاة نتائج صفحات تسجيل الدخول
            common_admin_paths = [
                '/admin/login.php',
                '/administrator/index.php',
                '/wp-admin/',
                '/admin/',
                '/panel/login',
                '/admin/login.html',
                '/administrator/login.php',
                '/admin.php',
                '/admin/login',
                '/administrator/'
            ]
            
            # استخراج النطاق من الاستعلام
            domain_match = re.search(r'site:([^\s]+)', query)
            if domain_match:
                domain = domain_match.group(1)
                
                # إنشاء نتائج محاكاة
                for i, path in enumerate(common_admin_paths[:max_results]):
                    url = f"https://{domain}{path}"
                    results.append({
                        'title': f'Admin Login - {path}',
                        'url': url,
                        'description': f'Administration panel login page for {domain}',
                        'category': 'admin_login'
                    })
        
        elif 'index of' in query.lower():
            # محاكاة نتائج الدلائل المفتوحة
            common_dirs = [
                '/admin/',
                '/backup/',
                '/logs/',
                '/config/',
                '/uploads/',
                '/files/',
                '/downloads/',
                '/temp/'
            ]
            
            domain_match = re.search(r'site:([^\s]+)', query)
            if domain_match:
                domain = domain_match.group(1)
                
                for i, dir_path in enumerate(common_dirs[:max_results]):
                    url = f"https://{domain}{dir_path}"
                    results.append({
                        'title': f'Index of {dir_path}',
                        'url': url,
                        'description': f'Directory listing for {dir_path} on {domain}',
                        'category': 'open_directory'
                    })
        
        elif any(ext in query.lower() for ext in ['.env', '.config', '.sql', '.backup']):
            # محاكاة نتائج الملفات الحساسة
            sensitive_files = [
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/database.sql',
                '/backup.sql',
                '/config.bak',
                '/settings.ini',
                '/phpinfo.php'
            ]
            
            domain_match = re.search(r'site:([^\s]+)', query)
            if domain_match:
                domain = domain_match.group(1)
                
                for i, file_path in enumerate(sensitive_files[:max_results]):
                    url = f"https://{domain}{file_path}"
                    results.append({
                        'title': f'{file_path} - Configuration File',
                        'url': url,
                        'description': f'Sensitive configuration file found on {domain}',
                        'category': 'config_file'
                    })
        
        # تأخير محاكاة
        time.sleep(random.uniform(0.1, self.delay))
        
        return results[:max_results]
    
    def scan_target(self, target_url: str, categories: List[str] = None, max_results_per_dork: int = 5) -> Dict[str, Any]:
        """
        مسح الهدف باستخدام Google Dorks
        
        Args:
            target_url: الرابط المستهدف
            categories: قائمة الفئات للبحث (اختياري)
            max_results_per_dork: الحد الأقصى للنتائج لكل استعلام
        
        Returns:
            تقرير شامل بنتائج البحث
        """
        
        if categories is None:
            categories = list(self.dorks_templates.keys())
        
        domain = self.extract_domain(target_url)
        queries = self.build_dork_queries(domain)
        
        results = {
            'target_url': target_url,
            'domain': domain,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': categories,
            'total_findings': 0,
            'findings': {},
            'summary': {
                'admin_login_pages': 0,
                'admin_directories': 0,
                'config_files': 0,
                'backup_files': 0,
                'open_directories': 0,
                'sensitive_pages': 0,
                'log_files': 0,
                'total_risk_score': 0
            }
        }
        
        total_findings = 0
        
        for category in categories:
            if category not in queries:
                continue
            
            category_results = []
            category_queries = queries[category]
            
            for query in category_queries:
                query_results = self.search_with_dork(query, max_results_per_dork)
                category_results.extend(query_results)
                total_findings += len(query_results)
            
            # إزالة التكرارات
            seen_urls = set()
            unique_results = []
            for result in category_results:
                if result['url'] not in seen_urls:
                    seen_urls.add(result['url'])
                    unique_results.append(result)
            
            results['findings'][category] = unique_results
            results['summary'][f'{category}_count'] = len(unique_results)
        
        results['total_findings'] = total_findings
        
        # حساب درجة الخطورة
        risk_weights = {
            'admin_login': 8,
            'config_file': 9,
            'backup_file': 7,
            'open_directory': 5,
            'sensitive_page': 6,
            'admin_directories': 7,
            'log_files': 6
        }
        
        total_risk = 0
        for category, findings in results['findings'].items():
            weight = risk_weights.get(category, 5)
            total_risk += len(findings) * weight
        
        results['summary']['total_risk_score'] = total_risk
        
        # تصنيف مستوى الخطورة
        if total_risk >= 30:
            results['summary']['risk_level'] = 'HIGH'
        elif total_risk >= 15:
            results['summary']['risk_level'] = 'MEDIUM'
        elif total_risk >= 5:
            results['summary']['risk_level'] = 'LOW'
        else:
            results['summary']['risk_level'] = 'INFO'
        
        return results
    
    def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """توليد تقرير نصي شامل"""
        
        report = f"""\تقرير Google Dorks لاكتشاف الصفحات الإدارية
========================================

الموقع المستهدف: {scan_results['target_url']}
النطاق: {scan_results['domain']}
تاريخ الفحص: {scan_results['scan_timestamp']}

الملخص:
- إجمالي النتائج: {scan_results['total_findings']}
- درجة الخطورة: {scan_results['summary']['risk_level']} ({scan_results['summary']['total_risk_score']})

التفاصيل حسب الفئة:
"""
        
        for category, findings in scan_results['findings'].items():
            if findings:
                category_name = category.replace('_', ' ').title()
                report += f"\n{category_name} ({len(findings)}):\n"
                for finding in findings:
                    report += f"  - {finding['title']}: {finding['url']}\n"
                    if finding.get('description'):
                        report += f"    الوصف: {finding['description']}\n"
        
        report += """
التوصيات:
1. تأكد من حماية جميع الصفحات الإدارية بمصادقة قوية
2. لا تترك الملفات الحساسة في أماكن يمكن الوصول إليها
3. استخدم ملف robots.txt لمنع أدوات البحث من فهرسة الدلائل الحساسة
4. قم بتشفير الملفات الإعدادية والنسخ الاحتياطية
5. راقب الوصول إلى الصفحات الإدارية بانتظام

ملاحظة: هذه النتائج من محاكاة البحث. في التطبيق الفعلي، استخدم Google Custom Search API.
"""
        
        return report
    
    def export_results(self, scan_results: Dict[str, Any], format: str = 'json') -> str:
        """تصدير النتائج بصيغ مختلفة"""
        
        if format.lower() == 'json':
            return json.dumps(scan_results, ensure_ascii=False, indent=2)
        
        elif format.lower() == 'txt':
            return self.generate_report(scan_results)
        
        else:
            raise ValueError("تنسيق غير مدعوم. استخدم 'json' أو 'txt'")
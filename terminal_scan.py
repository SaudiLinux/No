#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
from urllib.parse import urlparse
import time

class TerminalScanner:
    def __init__(self):
        self.results = []
        
    def scan_target(self, target):
        print('='*60)
        print(f'🎯 بدء المسح الأمني لـ: {target}')
        print('='*60)
        
        # فحص النطاق الأساسي
        print('📡 فحص معلومات النطاق...')
        domain_info = self.get_domain_info(target)
        
        # فحص الملفات الشائعة
        print('🔍 فحص الملفات الحساسة...')
        sensitive_files = self.scan_sensitive_files(target)
        
        # فحص الثغرات الأساسية
        print('⚠️ فحص الثغرات الأمنية...')
        vulnerabilities = self.scan_vulnerabilities(target)
        
        # عرض النتائج
        self.display_results(target, domain_info, sensitive_files, vulnerabilities)
        
        # حفظ النتائج
        self.save_results(target, domain_info, sensitive_files, vulnerabilities)
        
    def get_domain_info(self, target):
        try:
            parsed = urlparse(target)
            domain = parsed.netloc
            return {
                'domain': domain,
                'scheme': parsed.scheme,
                'path': parsed.path
            }
        except:
            return {'domain': target, 'error': 'Invalid URL'}
    
    def scan_sensitive_files(self, target):
        files_to_check = [
            '/robots.txt',
            '/sitemap.xml',
            '/.env',
            '/config.php',
            '/admin/',
            '/backup/',
            '/logs/',
            '/.htaccess',
            '/phpinfo.php',
            '/test.php'
        ]
        
        found_files = []
        base_url = target.rstrip('/')
        
        for file_path in files_to_check:
            try:
                url = base_url + file_path
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    found_files.append({
                        'path': file_path,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    print(f'✅ تم العثور على: {file_path}')
            except:
                pass
                
        return found_files
    
    def scan_vulnerabilities(self, target):
        vulns = []
        
        # فحص XSS بسيط
        xss_payloads = ['<script>alert(1)</script>', 'javascript:alert(1)']
        test_urls = [f'{target}/search?q=test', f'{target}/?page=1']
        
        for url in test_urls:
            try:
                for payload in xss_payloads:
                    test_url = url + payload
                    response = requests.get(test_url, timeout=5, verify=False)
                    if payload in response.text:
                        vulns.append({
                            'type': 'XSS',
                            'url': test_url,
                            'severity': 'medium',
                            'description': 'احتمال وجود ثغرة XSS'
                        })
                        print(f'⚠️ تم اكتشاف احتمالية XSS: {test_url}')
            except:
                pass
        
        return vulns
    
    def display_results(self, target, domain_info, files, vulns):
        print('\n' + '='*60)
        print('📊 نتائج المسح')
        print('='*60)
        
        print(f'🌐 النطاق: {domain_info.get("domain", "غير معروف")}')
        print(f'🔐 الملفات الحساسة: {len(files)}')
        print(f'⚠️ الثغرات المحتملة: {len(vulns)}')
        
        if files:
            print('\n📁 الملفات المكتشفة:')
            for file in files:
                print(f'  • {file["path"]} ({file["size"]} بايت)')
        
        if vulns:
            print('\n🚨 الثغرات المحتملة:')
            for vuln in vulns:
                print(f'  • {vuln["type"]} - {vuln["severity"]}')
        
        print('\n✅ تم إكمال المسح بنجاح!')
    
    def save_results(self, target, domain_info, files, vulns):
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f'terminal_scan_{timestamp}.json'
        
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'domain_info': domain_info,
            'sensitive_files': files,
            'vulnerabilities': vulns,
            'summary': {
                'total_files': len(files),
                'total_vulnerabilities': len(vulns)
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f'💾 تم حفظ النتائج في: {filename}')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = 'https://www.gov.il'
    
    scanner = TerminalScanner()
    scanner.scan_target(target)
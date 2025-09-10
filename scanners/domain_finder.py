import requests
import json
import time
import random
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import whois
from datetime import datetime

class IsraeliDomainFinder:
    def __init__(self):
        self.israeli_tlds = ['.il', '.co.il', '.org.il', '.gov.il', '.ac.il', '.muni.il']
        self.found_domains = set()
        self.session = requests.Session()
        
    def is_israeli_domain(self, domain):
        """التحقق إن كان النطاق إسرائيلي"""
        domain = domain.lower()
        return any(domain.endswith(tld) for tld in self.israeli_tlds)
    
    def search_by_keywords(self, keywords):
        """البحث عن نطاقات إسرائيلية باستخدام كلمات مفتاحية"""
        israeli_domains = []
        
        for keyword in keywords:
            # البحث عن النطاقات المرتبطة بالكلمات المفتاحية
            domains = self._generate_domains_from_keyword(keyword)
            for domain in domains:
                if self.is_israeli_domain(domain):
                    israeli_domains.append(domain)
        
        return list(set(israeli_domains))
    
    def _generate_domains_from_keyword(self, keyword):
        """توليد نطاقات محتملة من كلمة مفتاحية"""
        domains = []
        prefixes = ['www.', 'mail.', 'ftp.', 'admin.', 'api.']
        suffixes = ['', '1', '2', '3', 'online', 'web', 'site']
        
        keyword = keyword.lower().strip()
        
        # توليد النطاقات المختلفة
        for tld in self.israeli_tlds:
            for prefix in prefixes:
                for suffix in suffixes:
                    domain = f"{prefix}{keyword}{suffix}{tld}"
                    domains.append(domain)
        
        return domains
    
    def find_active_domains(self, domains):
        """العثور على النطاقات النشطة"""
        active_domains = []
        
        def check_domain(domain):
            try:
                # التحقق من DNS
                socket.gethostbyname(domain)
                return domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
            for future in as_completed(future_to_domain):
                result = future.result()
                if result:
                    active_domains.append(result)
        
        return active_domains
    
    def get_domain_info(self, domain):
        """الحصول على معلومات مفصلة عن النطاق"""
        try:
            # معلومات WHOIS
            domain_info = whois.whois(domain)
            
            # معلومات DNS
            dns_info = {
                'A': [],
                'MX': [],
                'NS': [],
                'TXT': []
            }
            
            for record_type in dns_info.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
                except:
                    pass
            
            return {
                'domain': domain,
                'whois': str(domain_info),
                'dns': dns_info,
                'timestamp': str(datetime.now())
            }
        except Exception as e:
            return {
                'domain': domain,
                'error': str(e),
                'timestamp': str(datetime.now())
            }
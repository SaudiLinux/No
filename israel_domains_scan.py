#!/usr/bin/env python3
"""
أداة بحث متقدمة عن المواقع الإسرائيلية
بتقنية سعودية متقدمة للدفاع السيبراني 🇸🇦
"""

import requests
import json
import socket
import subprocess
import os
from datetime import datetime

class IsraelDomainScanner:
    def __init__(self):
        self.israeli_domains = []
        self.gov_domains = []
        self.mil_domains = []
        self.edu_domains = []
        self.org_domains = []
        
        # قائمة النطاقات الإسرائيلية الرئيسية
        self.israeli_tlds = ['.il', '.co.il', '.org.il', '.gov.il', '.ac.il', '.muni.il']
        
        # المواقع الحكومية الإسرائيلية المعروفة
        self.known_israeli_sites = [
            'www.gov.il',
            'www.mfa.gov.il',
            'www.knesset.gov.il',
            'www.pmo.gov.il',
            'www.mof.gov.il',
            'www.mod.gov.il',
            'www.police.gov.il',
            'www.cbs.gov.il',
            'www.moit.gov.il',
            'www.health.gov.il',
            'www.education.gov.il',
            'www.justice.gov.il',
            'www.transportation.gov.il',
            'www.energy.gov.il',
            'www.agriculture.gov.il',
            'www.tourism.gov.il',
            'www.israelpost.co.il',
            'www.bankisrael.gov.il',
            'www.court.gov.il',
            'www.maya.gov.il',
            'www.piba.gov.il',
            'www.mda.org.il',
            'www.idf.il',
            'www.mod.idf.il',
            'www.iaf.idf.il',
            'www.navy.idf.il',
            'www.shabak.gov.il',
            'www.mossad.gov.il',
            'www.israel-mfa.gov.il',
            'www.embassies.gov.il'
        ]
        
        # الجامعات الإسرائيلية
        self.israeli_universities = [
            'www.huji.ac.il',
            'www.tau.ac.il',
            'www.technion.ac.il',
            'www.bgu.ac.il',
            'www.haifa.ac.il',
            'www.biu.ac.il',
            'www.openu.ac.il',
            'www.wgalil.ac.il',
            'www.ariel.ac.il',
            'www.jct.ac.il'
        ]
        
        # الشركات التكنولوجيا الإسرائيلية
        self.israeli_tech_companies = [
            'www.wix.com',
            'www.fiverr.com',
            'www.monday.com',
            'www.ironscales.com',
            'www.cyberark.com',
            'www.checkpoint.com',
            'www.nice.com',
            'www.amdocs.com',
            'www.mobileye.com',
            'www.waze.com'
        ]

    def check_domain_alive(self, domain):
        """التحقق من أن النطاق نشط"""
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False

    def scan_domain(self, domain):
        """فحص النطاق للحصول على معلومات"""
        result = {
            'domain': domain,
            'is_alive': False,
            'ip_address': None,
            'open_ports': [],
            'services': {},
            'risk_level': 'UNKNOWN',
            'vulnerabilities': []
        }
        
        try:
            # التحقق من النشاط
            if self.check_domain_alive(domain):
                result['is_alive'] = True
                result['ip_address'] = socket.gethostbyname(domain)
                
                # فحص المنافذ الأساسية
                common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995]
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock_result = sock.connect_ex((domain, port))
                        if sock_result == 0:
                            result['open_ports'].append(port)
                        sock.close()
                    except:
                        pass
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def generate_comprehensive_report(self):
        """إنشاء تقرير شامل عن المواقع الإسرائيلية"""
        
        print("🏴 إطلاق عملية البحث الشاملة عن المواقع الإسرائيلية 🇸🇦")
        print("=" * 60)
        
        all_domains = []
        
        # جمع جميع النطاقات
        all_domains.extend(self.known_israeli_sites)
        all_domains.extend(self.israeli_universities)
        all_domains.extend(self.israeli_tech_companies)
        
        # إزالة التكرارات
        all_domains = list(set(all_domains))
        
        results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_domains_checked': len(all_domains),
            'alive_domains': [],
            'dead_domains': [],
            'government_sites': [],
            'military_sites': [],
            'education_sites': [],
            'tech_companies': [],
            'summary': {}
        }
        
        print(f"📊 إجمالي النطاقات للفحص: {len(all_domains)}")
        print()
        
        alive_count = 0
        for domain in all_domains:
            print(f"🔍 فحص: {domain}")
            scan_result = self.scan_domain(domain)
            
            if scan_result['is_alive']:
                alive_count += 1
                results['alive_domains'].append(scan_result)
                
                # تصنيف النطاق
                if 'gov.il' in domain:
                    results['government_sites'].append(scan_result)
                elif 'idf.il' in domain or 'mod.' in domain:
                    results['military_sites'].append(scan_result)
                elif 'ac.il' in domain:
                    results['education_sites'].append(scan_result)
                elif domain in self.israeli_tech_companies:
                    results['tech_companies'].append(scan_result)
                    
            else:
                results['dead_domains'].append(domain)
        
        # إنشاء ملخص
        results['summary'] = {
            'total_checked': len(all_domains),
            'alive_count': alive_count,
            'dead_count': len(all_domains) - alive_count,
            'government_count': len(results['government_sites']),
            'military_count': len(results['military_sites']),
            'education_count': len(results['education_sites']),
            'tech_companies_count': len(results['tech_companies'])
        }
        
        # حفظ النتائج
        filename = f'israel_domains_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        # عرض النتائج
        print()
        print("🏆 نتائج البحث الشاملة:")
        print("=" * 60)
        print(f"📊 إجمالي النطاقات: {results['summary']['total_checked']}")
        print(f"✅ النطاقات النشطة: {results['summary']['alive_count']}")
        print(f"❌ النطاقات غير النشطة: {results['summary']['dead_count']}")
        print(f"🏛️ المواقع الحكومية: {results['summary']['government_count']}")
        print(f"⚔️ المواقع العسكرية: {results['summary']['military_count']}")
        print(f"🎓 الجامعات: {results['summary']['education_count']}")
        print(f"💻 شركات التكنولوجيا: {results['summary']['tech_companies_count']}")
        print()
        print(f"📄 تم حفظ النتائج في: {filename}")
        
        # عرض المواقع النشطة
        if results['alive_domains']:
            print()
            print("🌐 المواقع الإسرائيلية النشطة:")
            print("-" * 40)
            for site in results['alive_domains']:
                print(f"🔗 {site['domain']} ({site['ip_address']})")
                if site['open_ports']:
                    print(f"   📡 المنافذ المفتوحة: {', '.join(map(str, site['open_ports']))}")
        
        return results

    def search_additional_domains(self):
        """البحث عن نطاقات إضافية"""
        additional_domains = [
            # البنوك الإسرائيلية
            'www.bankleumi.co.il',
            'www.bankhapoalim.co.il',
            'www.israeldiscountbank.co.il',
            'www.mizrahi-tefahot.co.il',
            'www.firstinternational.com',
            
            # شركات الطيران
            'www.elal.com',
            'www.israir.co.il',
            'www.arkia.co.il',
            
            # وسائل الإعلام
            'www.ynet.co.il',
            'www.haaretz.co.il',
            'www.jpost.com',
            'www.timesofisrael.com',
            
            # شركات التكنولوجيا
            'www.intel.com/il',
            'www.microsoft.com/il-he-il',
            'www.google.co.il',
            'www.facebook.com/Israel'
        ]
        
        return additional_domains

if __name__ == "__main__":
    scanner = IsraelDomainScanner()
    
    print("🚀 بدء عملية المسح الشاملة للمواقع الإسرائيلية 🇸🇦")
    print("=" * 70)
    print("هذه الأداة تقوم بالبحث عن جميع المواقع الإسرائيلية")
    print("بما في ذلك المواقع الحكومية، العسكرية، التعليمية، والتجارية")
    print()
    
    # تشغيل المسح الشامل
    results = scanner.generate_comprehensive_report()
    
    print()
    print("✅ اكتملت عملية المسح بنجاح!")
    print("يمكنك الآن استخدام النتائج لتحليل الأمن السيبراني للمواقع الإسرائيلية")
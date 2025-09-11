from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import threading
import time
from datetime import datetime
from scanners.domain_finder import IsraeliDomainFinder
import logging

app = Flask(__name__)

# إعداد التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# متغيرات الحالة العامة
finder = IsraeliDomainFinder()
scan_status = {
    'is_running': False,
    'current_phase': '',
    'domains_found': 0,
    'vulnerabilities_found': 0,
    'progress': 0,
    'results': [],
    'start_time': None,
    'estimated_completion': None
}

vulnerability_scan_status = {
    'is_running': False,
    'current_target': '',
    'total_targets': 0,
    'completed_targets': 0,
    'vulnerabilities_found': 0,
    'progress': 0,
    'results': [],
    'nvd_citations': {}
}

stealth_config = {
    'use_proxy_rotation': True,
    'use_user_agent_rotation': True,
    'use_random_delay': True,
    'min_delay': 1,
    'max_delay': 5,
    'use_dns_rotation': True
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/dns_discovery', methods=['POST'])
def dns_discovery():
    data = request.json
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        results = finder.dns_enumeration(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stealth_config', methods=['POST'])
def update_stealth_config():
    global stealth_config
    data = request.json
    stealth_config.update(data)
    return jsonify({'success': True, 'config': stealth_config})

@app.route('/api/attack_surface', methods=['GET'])
def get_attack_surface():
    rotation = finder.rotate_attack_surface()
    return jsonify(rotation)

@app.route('/api/start_vulnerability_scan', methods=['POST'])
def start_vulnerability_scan():
    global vulnerability_scan_status
    
    if vulnerability_scan_status['is_running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.json
    domains = data.get('domains', [])
    
    if not domains:
        return jsonify({'error': 'Domains are required'}), 400
    
    def run_scan():
        global vulnerability_scan_status
        vulnerability_scan_status.update({
            'is_running': True,
            'current_target': '',
            'total_targets': len(domains),
            'completed_targets': 0,
            'vulnerabilities_found': 0,
            'progress': 0,
            'results': [],
            'nvd_citations': {}
        })
        
        try:
            # مسح شامل للثغرات مع استشهادات NVD
            scan_results = finder.comprehensive_vulnerability_scan_with_nvd(domains)
            
            vulnerability_scan_status.update({
                'results': scan_results['vulnerable_domains'],
                'nvd_citations': scan_results['vulnerability_citations'],
                'vulnerabilities_found': sum(len(domain.get('vulnerabilities', [])) 
                                           for domain in scan_results['vulnerable_domains']),
                'progress': 100
            })
            
        except Exception as e:
            logger.error(f"Error in vulnerability scan: {e}")
            vulnerability_scan_status['error'] = str(e)
        finally:
            vulnerability_scan_status['is_running'] = False
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Vulnerability scan started'})

@app.route('/api/vulnerability_status', methods=['GET'])
def get_vulnerability_status():
    return jsonify(vulnerability_scan_status)

@app.route('/api/get_domains', methods=['GET'])
def get_domains():
    return jsonify({
        'domains': scan_status.get('results', []),
        'vulnerable_domains': vulnerability_scan_status.get('results', [])
    })

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    global scan_status
    
    if scan_status['is_running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.json
    keywords = data.get('keywords', [])
    use_stealth = data.get('use_stealth', True)
    
    if not keywords:
        return jsonify({'error': 'Keywords are required'}), 400
    
    def run_scan():
        global scan_status, vulnerability_scan_status
        
        scan_status.update({
            'is_running': True,
            'current_phase': 'Initializing scan...',
            'domains_found': 0,
            'vulnerabilities_found': 0,
            'progress': 0,
            'results': [],
            'start_time': datetime.now().isoformat(),
            'estimated_completion': None
        })
        
        try:
            # إعداد التكوين للمسح الشامل
            config = stealth_config if use_stealth else None
            
            # اكتشاف النطاقات
            scan_status['current_phase'] = 'Discovering domains...'
            scan_status['progress'] = 25
            
            results = finder.comprehensive_domain_discovery(keywords, config)
            scan_status['results'] = results['discovered_domains']
            scan_status['domains_found'] = len(results['discovered_domains'])
            
            # فحص الثغرات للنطاقات المكتشفة
            scan_status['current_phase'] = 'Scanning vulnerabilities...'
            scan_status['progress'] = 50
            
            # استخراج النطاقات للفحص
            domains_to_scan = []
            for domain_info in results['discovered_domains']:
                domain = domain_info['keyword']
                if domain_info.get('dns_records', {}).get('A'):
                    domains_to_scan.append(domain)
            
            if domains_to_scan:
                scan_results = finder.comprehensive_vulnerability_scan_with_nvd(domains_to_scan)
                vulnerability_scan_status.update({
                    'results': scan_results['vulnerable_domains'],
                    'nvd_citations': scan_results['vulnerability_citations']
                })
                scan_status['vulnerabilities_found'] = sum(len(domain.get('vulnerabilities', [])) 
                                                          for domain in scan_results['vulnerable_domains'])
            
            scan_status['current_phase'] = 'Completed'
            scan_status['progress'] = 100
            
        except Exception as e:
            logger.error(f"Error in scan: {e}")
            scan_status['error'] = str(e)
        finally:
            scan_status['is_running'] = False
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Scan started'})

@app.route('/api/scan_status', methods=['GET'])
def get_scan_status():
    return jsonify(scan_status)

@app.route('/api/nvd_info/<cve_id>', methods=['GET'])
def get_nvd_info(cve_id):
    """الحصول على معلومات CVE من NVD مع DOI"""
    try:
        cve_info = finder.get_nvd_cve_info(cve_id)
        return jsonify(cve_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/nvd_statistics', methods=['GET'])
def get_nvd_statistics():
    """الحصول على إحصائيات NVD"""
    try:
        stats = finder.get_nvd_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cve_by_product', methods=['POST'])
def get_cve_by_product():
    """الحصول على CVEs حسب المنتج"""
    data = request.json
    product = data.get('product', '')
    version = data.get('version', None)
    
    if not product:
        return jsonify({'error': 'Product name is required'}), 400
    
    try:
        cves = finder.get_cve_by_product(product, version)
        return jsonify({'cves': cves, 'product': product, 'version': version})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# تعديل اسم الدالة لتجنب التكرار
@app.route('/api/nvd_citations', methods=['GET'])
def get_nvd_citations():
    """الحصول على استشهادات رسمية للثغرات من NVD"""
    vulnerability_type = request.args.get('type', 'all')
    
    try:
        if vulnerability_type == 'all':
            citations = {}
            for vuln_type in ['log4j', 'directory_traversal', 'sql_injection', 'xss', 'ssl_tls']:
                citations[vuln_type] = finder.get_vulnerability_citations(vuln_type)
        else:
            citations = finder.get_vulnerability_citations(vulnerability_type)
        
        return jsonify({'citations': citations})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stealth_report/<scan_id>')
def generate_stealth_report(scan_id):
    report = finder.generate_stealth_report(scan_id)
    return jsonify(report)

@app.route('/api/export_results', methods=['POST'])
def export_results():
    data = request.json
    results = data.get('results', [])
    format_type = data.get('format', 'json')
    
    if not results:
        return jsonify({'error': 'No results to export'}), 400
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'scan_results_{timestamp}.{format_type}'
    filepath = os.path.join('exports', filename)
    
    # إنشاء مجلد التصدير إذا لم يكن موجوداً
    os.makedirs('exports', exist_ok=True)
    
    try:
        if format_type == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        elif format_type == 'txt':
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Scan Results - {datetime.now()}\n")
                f.write("=" * 50 + "\n\n")
                for result in results:
                    f.write(f"Domain: {result.get('domain', 'N/A')}\n")
                    f.write(f"Risk Level: {result.get('risk_level', 'N/A')}\n")
                    f.write(f"Vulnerabilities: {len(result.get('vulnerabilities', []))}\n")
                    f.write("-" * 30 + "\n")
        
        return jsonify({'success': True, 'filename': filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# إضافة مسارات جديدة لصفحة البحث المتقدمة NVD
@app.route('/nvd_search')
def nvd_search_page():
    return render_template('nvd_search.html')

# إعادة توجيه عناوين URL القديمة
@app.route('/vuln/search/results')
def redirect_old_results():
    return redirect('https://nvd.nist.gov/vuln/search#/nvd/home?resultType=records', code=301)

@app.route('/vuln/search/statistics')
def redirect_old_statistics():
    return redirect('https://nvd.nist.gov/vuln/search#/nvd/home?resultType=statistics', code=301)

# API جديد للبحث المتقدم في NVD
@app.route('/api/nvd_search', methods=['POST'])
def nvd_advanced_search():
    try:
        data = request.json
        
        # بناء معلمات البحث
        params = {
            'keyword': data.get('query', ''),
            'cvssV3Severity': ','.join(data.get('severity', [])),
            'resultsPerPage': data.get('limit', 20),
            'startIndex': (data.get('page', 1) - 1) * data.get('limit', 20)
        }
        
        # إضافة فلاتر إضافية
        if data.get('cveId'):
            params['cveId'] = data.get('cveId')
        if data.get('year'):
            params['pubStartDate'] = f"{data['year']}-01-01T00:00:00:000 UTC"
            params['pubEndDate'] = f"{data['year']}-12-31T23:59:59:000 UTC"
        if data.get('cvssMin') or data.get('cvssMax') < 10:
            params['cvssV3Score'] = f"{data.get('cvssMin', 0)}-{data.get('cvssMax', 10)}"
            
        # إرسال طلب إلى NVD API
        nvd_response = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params=params,
            headers={'User-Agent': 'NVD-Advanced-Search-Tool/1.0'}
        )
        
        if nvd_response.status_code == 200:
            nvd_data = nvd_response.json()
            
            # معالجة النتائج
            vulnerabilities = []
            for vuln in nvd_data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                
                # استخراج DOI من المراجع
                doi = None
                for ref in cve.get('references', []):
                    if 'doi.org' in ref.get('url', ''):
                        doi = ref['url']
                        break
                
                # استخراج معلومات المنتج
                product_name = 'غير محدد'
                version = ''
                for node in cve.get('configurations', {}).get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('criteria'):
                            parts = cpe_match['criteria'].split(':')
                            if len(parts) >= 5:
                                product_name = parts[4]
                                if len(parts) >= 6:
                                    version = parts[5]
                                break
                
                # استخراج درجة CVSS
                cvss_score = None
                if 'metrics' in cve:
                    if 'cvssMetricV31' in cve['metrics']:
                        cvss_score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in cve['metrics']:
                        cvss_score = cve['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                
                vulnerabilities.append({
                    'id': cve.get('id', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', 'لا يوجد وصف'),
                    'severity': cve.get('descriptions', [{}])[0].get('value', '').split()[0].upper() if 'CRITICAL' in cve.get('descriptions', [{}])[0].get('value', '').upper() else 'MEDIUM',
                    'cvss_score': cvss_score,
                    'product_name': product_name,
                    'version': version,
                    'published_date': cve.get('published', '').split('T')[0],
                    'doi': doi,
                    'tags': [tag for tag in cve.get('descriptions', [{}])[0].get('value', '').split() if len(tag) > 3]
                })
            
            return jsonify({
                'success': True,
                'vulnerabilities': vulnerabilities,
                'totalResults': nvd_data.get('totalResults', 0),
                'resultsPerPage': nvd_data.get('resultsPerPage', 20),
                'startIndex': nvd_data.get('startIndex', 0)
            })
        else:
            return jsonify({
                'success': False,
                'error': f'فشل في الاتصال بـ NVD API: {nvd_response.status_code}'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# إضافة مسار لإحصائيات NVD
@app.route('/api/nvd_statistics')
def nvd_statistics():
    try:
        # الحصول على إحصائيات عامة من NVD
        stats_response = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1',
            headers={'User-Agent': 'NVD-Statistics-Tool/1.0'}
        )
        
        if stats_response.status_code == 200:
            stats_data = stats_response.json()
            
            # حساب الإحصائيات حسب السنة
            current_year = datetime.now().year
            yearly_stats = {}
            
            for year in range(current_year - 5, current_year + 1):
                year_response = requests.get(
                    f'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00:000 UTC&pubEndDate={year}-12-31T23:59:59:000 UTC',
                    headers={'User-Agent': 'NVD-Statistics-Tool/1.0'}
                )
                
                if year_response.status_code == 200:
                    year_data = year_response.json()
                    yearly_stats[str(year)] = year_data.get('totalResults', 0)
            
            return jsonify({
                'success': True,
                'totalCVEs': stats_data.get('totalResults', 0),
                'yearlyStats': yearly_stats,
                'lastUpdated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({
                'success': False,
                'error': 'فشل في الصحول على الإحصائيات'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/vulnerability_citations', methods=['GET'])
def get_vulnerability_citations():
    """الحصول على استشهادات رسمية للثغرات"""
    vulnerability_type = request.args.get('type', 'all')
    
    try:
        if vulnerability_type == 'all':
            citations = {}
            for vuln_type in ['log4j', 'directory_traversal', 'sql_injection', 'xss', 'ssl_tls']:
                citations[vuln_type] = finder.get_vulnerability_citations(vuln_type)
        else:
            citations = finder.get_vulnerability_citations(vulnerability_type)
        
        return jsonify({'citations': citations})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hidden_links/scan', methods=['POST'])
def scan_hidden_links():
    """
    مسح الروابط الخفية للموقع المستهدف وفحصها للثغرات
    """
    try:
        data = request.get_json()
        target_url = data.get('url', '').strip()
        
        if not target_url:
            return jsonify({
                'error': 'يرجى تقديم رابط الموقع المستهدف',
                'status': 'error'
            }), 400
        
        # التحقق من صحة الرابط
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # استيراد الماسح الجديد
        from scanners.hidden_links_scanner import HiddenLinksScanner
        
        scanner = HiddenLinksScanner()
        
        # تشغيل الفحص
        report = scanner.generate_comprehensive_report(target_url)
        
        return jsonify({
            'status': 'success',
            'target_url': target_url,
            'scan_timestamp': report['scan_timestamp'],
            'summary': report['summary'],
            'hidden_links': report['hidden_links'],
            'vulnerabilities': report['vulnerabilities'],
            'recommendations': report['recommendations']
        })
        
    except Exception as e:
        return jsonify({
            'error': f'خطأ في الفحص: {str(e)}',
            'status': 'error'
        }), 500

@app.route('/hidden_links')
def hidden_links_page():
    """
    صفحة واجهة المستخدم لاكتشاف الروابط الخفية
    """
    return render_template('hidden_links.html')

@app.route('/api/hidden_links/export/<format>', methods=['POST'])
def export_hidden_links_report(format):
    """
    تصدير تقرير الروابط الخفية
    """
    try:
        data = request.get_json()
        report_data = data.get('report', {})
        
        if format == 'json':
            return jsonify(report_data)
        
        elif format == 'txt':
            # توليد تقرير نصي
            report_text = f"""
تقرير فحص الروابط الخفية والثغرات
================================

الموقع المستهدف: {report_data.get('target_url', 'N/A')}
تاريخ الفحص: {report_data.get('scan_timestamp', 'N/A')}

ملخص النتائج:
- إجمالي الروابط الخفية: {report_data.get('summary', {}).get('total_hidden_links', 0)}
- الروابط المعرضة للخطر: {report_data.get('summary', {}).get('vulnerable_links', 0)}
- إجمالي الثغرات: {report_data.get('summary', {}).get('total_vulnerabilities', 0)}
- مستوى الخطورة: {report_data.get('summary', {}).get('risk_level', 'N/A')}

الروابط الخفية المكتشفة:
"""
            
            for link in report_data.get('hidden_links', []):
                report_text += f"- {link['url']} (المصدر: {link['source']})\n"
            
            if report_data.get('vulnerabilities'):
                report_text += "\nالثغرات المكتشفة:\n"
                for vuln in report_data.get('vulnerabilities', []):
                    report_text += f"- [{vuln['severity']}] {vuln['vulnerability_type']} في {vuln['url']}\n"
            
            report_text += "\nالتوصيات الأمنية:\n"
            for rec in report_data.get('recommendations', []):
                report_text += f"- {rec}\n"
            
            response = make_response(report_text)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            response.headers['Content-Disposition'] = 'attachment; filename=hidden_links_report.txt'
            return response
            
        else:
            return jsonify({'error': 'تنسيق غير مدعوم'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# إضافة مسار لاختبار استغلال الثغرات
from scanners.exploitation_tester import ExploitationTester

@app.route('/api/exploitation/test', methods=['POST'])
def test_exploitation():
    """اختبار استغلال الثغرات في وضع آمن"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        vulnerability_types = data.get('vulnerability_types', [])
        safe_mode = data.get('safe_mode', True)
        
        if not target_url:
            return jsonify({'success': False, 'error': 'URL غير مقدم'}), 400
        
        if not vulnerability_types:
            return jsonify({'success': False, 'error': 'أنواع الثغرات غير مقدمة'}), 400
        
        # إنشاء ماسح مع وضع الاختبار الآمن
        tester = ExploitationTester(safe_mode=safe_mode)
        
        # تشغيل الاختبارات
        results = tester.run_batch_tests(target_url, vulnerability_types)
        
        # تنسيق النتائج للعرض
        successful_exploits = []
        for vuln_result in results['detailed_results']:
            for result in vuln_result['results']:
                if 'indicators' in result or 'reflected' in result or result.get('status_code') == 200:
                    successful_exploits.append({
                        'vulnerability_type': result['vulnerability_type'],
                        'target_url': result.get('target_url', target_url),
                        'risk_level': result.get('risk_level', 'UNKNOWN')
                    })
        
        return jsonify({
            'success': True,
            'target_url': target_url,
            'summary': {
                'total_tests': results['summary']['total_tests'],
                'successful_exploits': len(successful_exploits),
                'failed_tests': results['summary']['failed_tests'],
                'safe_mode': safe_mode
            },
            'successful_exploits': successful_exploits,
            'detailed_results': results['detailed_results']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/exploitation/export/<format>', methods=['POST'])
def export_exploitation_report(format):
    """تصدير تقرير اختبار الاستغلال"""
    try:
        data = request.get_json()
        
        if format == 'json':
            # تصدير كـ JSON
            response = jsonify(data)
            response.headers['Content-Disposition'] = 'attachment; filename=exploitation_report.json'
            response.headers['Content-Type'] = 'application/json'
            return response
            
        elif format == 'txt':
            # إنشاء تقرير نصي
            tester = ExploitationTester()
            report = tester.generate_report(data)
            
            response = make_response(report)
            response.headers['Content-Disposition'] = 'attachment; filename=exploitation_report.txt'
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return response
            
        else:
            return jsonify({'success': False, 'error': 'تنسيق غير مدعوم'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# إضافة مسارات Google Dorks
from scanners.google_dorks_scanner import GoogleDorksScanner

@app.route('/api/google_dorks/scan', methods=['POST'])
def scan_google_dorks():
    """مسح Google Dorks لاكتشاف الصفحات الإدارية"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        categories = data.get('categories', None)
        max_results = data.get('max_results', 5)
        
        if not target_url:
            return jsonify({'success': False, 'error': 'URL غير مقدم'}), 400
        
        scanner = GoogleDorksScanner()
        results = scanner.scan_target(target_url, categories, max_results)
        
        return jsonify({
            'success': True,
            'target_url': target_url,
            'scan_timestamp': results['scan_timestamp'],
            'total_findings': results['total_findings'],
            'risk_level': results['summary']['risk_level'],
            'risk_score': results['summary']['total_risk_score'],
            'findings': results['findings'],
            'summary': results['summary']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/google_dorks/export/<format>', methods=['POST'])
def export_google_dorks_report(format):
    """تصدير تقرير Google Dorks"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results')
        
        if not scan_results:
            return jsonify({'success': False, 'error': 'لا توجد نتائج للتصدير'}), 400
        
        scanner = GoogleDorksScanner()
        
        if format.lower() == 'json':
            report = scanner.export_results(scan_results, 'json')
            response = make_response(report)
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['Content-Disposition'] = 'attachment; filename=google_dorks_report.json'
            return response
            
        elif format.lower() == 'txt':
            report = scanner.export_results(scan_results, 'txt')
            response = make_response(report)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            response.headers['Content-Disposition'] = 'attachment; filename=google_dorks_report.txt'
            return response
            
        else:
            return jsonify({'success': False, 'error': 'تنسيق غير مدعوم'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/google_dorks')
def google_dorks_page():
    """صفحة واجهة المستخدم لـ Google Dorks"""
    return render_template('google_dorks.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
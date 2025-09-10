from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import threading
from datetime import datetime
import sys
import importlib.util

# إضافة مسار المجلد الحالي
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanners.domain_finder import IsraeliDomainFinder
from scanners.vulnerability_scanner import VulnerabilityScanner
from scanners.hidden_files_scanner import HiddenFilesScanner

app = Flask(__name__)

# متغيرات التحكم في المسح
scan_status = {
    'is_running': False,
    'current_scan': None,
    'progress': 0,
    'results': [],
    'errors': []
}

@app.route('/')
def index():
    """الصفحة الرئيسية"""
    return render_template('index.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """بدء عملية المسح"""
    global scan_status
    
    if scan_status['is_running']:
        return jsonify({'error': 'مسح جار بالفعل'}), 400
    
    data = request.json
    scan_type = data.get('scan_type', 'all')
    target_urls = data.get('urls', [])
    
    if not target_urls:
        return jsonify({'error': 'لم يتم توفير عناوين URL'}), 400
    
    # تصفية المواقع الإسرائيلية فقط
    israeli_urls = [url for url in target_urls if '.il' in url.lower()]
    if not israeli_urls:
        return jsonify({'error': 'لم يتم العثور على مواقع إسرائيلية'}), 400
    
    scan_status = {
        'is_running': True,
        'current_scan': scan_type,
        'progress': 0,
        'results': [],
        'errors': []
    }
    
    # بدء المسح في خيط منفصل
    thread = threading.Thread(target=run_scan, args=(scan_type, israeli_urls))
    thread.start()
    
    return jsonify({'message': 'تم بدء المسح بنجاح', 'scan_id': 'current'})

@app.route('/api/scan_status')
def get_scan_status():
    """الحصول على حالة المسح"""
    return jsonify(scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    """إيقاف المسح"""
    global scan_status
    scan_status['is_running'] = False
    return jsonify({'message': 'تم إيقاف المسح'})

@app.route('/api/results')
def get_results():
    """الحصول على النتائج"""
    return jsonify(scan_status['results'])

@app.route('/api/download_report')
def download_report():
    """تحميل تقرير PDF"""
    report_data = {
        'scan_date': datetime.now().isoformat(),
        'results': scan_status['results'],
        'summary': generate_summary()
    }
    
    # حفظ التقرير كملف JSON
    report_path = 'results/scan_report.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    return send_file(report_path, as_attachment=True, download_name='israeli_sites_scan_report.json')

@app.route('/api/domains')
def get_domains():
    """الحصول على قائمة النطاقات الإسرائيلية"""
    finder = IsraeliDomainFinder()
    domains = finder.generate_israeli_domains()
    return jsonify({'domains': domains[:100]})  # أول 100 نطاق فقط

def run_scan(scan_type, urls):
    """تشغيل المسح"""
    global scan_status
    
    try:
        if scan_type in ['domains', 'all']:
            # مسح النطاقات
            finder = IsraeliDomainFinder()
            domains = [urlparse(url).netloc for url in urls]
            domain_results = finder.scan_domains(domains)
            scan_status['results'].extend(domain_results)
            scan_status['progress'] = 33
        
        if scan_type in ['vulnerabilities', 'all']:
            # مسح الثغرات
            scanner = VulnerabilityScanner()
            vuln_results = scanner.scan_multiple_websites(urls)
            scan_status['results'].extend(vuln_results)
            scan_status['progress'] = 66
        
        if scan_type in ['hidden_files', 'all']:
            # مسح الملفات المخفية
            file_scanner = HiddenFilesScanner()
            file_results = file_scanner.scan_multiple_websites(urls)
            scan_status['results'].extend(file_results)
            scan_status['progress'] = 100
        
        scan_status['is_running'] = False
        
    except Exception as e:
        scan_status['errors'].append(str(e))
        scan_status['is_running'] = False

def generate_summary():
    """إنشاء ملخص للنتائج"""
    summary = {
        'total_sites': 0,
        'vulnerabilities_found': 0,
        'hidden_files_found': 0,
        'domains_scanned': 0,
        'critical_issues': 0,
        'medium_issues': 0,
        'low_issues': 0
    }
    
    for result in scan_status['results']:
        if 'vulnerabilities' in result:
            summary['vulnerabilities_found'] += len(result['vulnerabilities'])
        if 'sensitive_files' in result:
            summary['hidden_files_found'] += len(result['sensitive_files'])
        if 'domain' in result:
            summary['domains_scanned'] += 1
        if 'url' in result:
            summary['total_sites'] += 1
    
    return summary

if __name__ == '__main__':
    # إنشاء مجلدات النتائج إذا لم تكن موجودة
    os.makedirs('results', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
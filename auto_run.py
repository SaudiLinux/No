#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess
import signal
import json
from datetime import datetime

class AutoRunner:
    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()
        
    def log(self, message, status="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{status}] {message}")
        
    def run_command(self, command, description, timeout=300):
        self.log(f"بدء: {description}")
        
        try:
            # إنشاء ملف سجل خاص بالأمر
            log_file = f"auto_run_{command.split()[1].split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            
            # تشغيل الأمر مباشرة بدون انتظار
            if 'app.py' in command:
                # تشغيل Flask في خلفية
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.getcwd()
                )
                time.sleep(3)  # انتظار بدء الخادم
                self.log(f"تم تشغيل خادم Flask في الخلفية", "SUCCESS")
                return {'status': 'success', 'process': process}
            else:
                # تشغيل الأوامر الأخرى بشكل متزامن
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=os.getcwd()
                )
                
                if result.returncode == 0:
                    self.log(f"اكتمل بنجاح: {description}", "SUCCESS")
                    return {
                        'status': 'success',
                        'stdout': result.stdout,
                        'stderr': result.stderr
                    }
                else:
                    self.log(f"اكتمل مع تحذير: {description}", "WARNING")
                    return {
                        'status': 'warning',
                        'stdout': result.stdout,
                        'stderr': result.stderr
                    }
                
        except subprocess.TimeoutExpired:
            process.kill()
            self.log(f"انتهاء الوقت: {description}", "TIMEOUT")
            return {'status': 'timeout', 'error': 'Command timed out'}
        except Exception as e:
            self.log(f"خطأ غير متوقع: {description} - {str(e)}", "ERROR")
            return {'status': 'exception', 'error': str(e)}
    
    def run_flask_server(self):
        """تشغيل خادم Flask في خلفية"""
        self.log("تشغيل خادم Flask...")
        
        # التحقق من أن الخادم غير مشغل بالفعل
        try:
            import requests
            requests.get('http://localhost:5000', timeout=2)
            self.log("الخادم يعمل بالفعل", "INFO")
            return {'status': 'already_running'}
        except:
            pass
        
        # تشغيل الخادم في خلفية
        process = subprocess.Popen(
            'python app.py',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # الانتظار قليلاً حتى يبدأ الخادم
        time.sleep(5)
        
        # التحقق من أن الخادم يعمل
        try:
            import requests
            response = requests.get('http://localhost:5000', timeout=5)
            if response.status_code == 200:
                self.log("تم تشغيل خادم Flask بنجاح", "SUCCESS")
                return {'status': 'success', 'process': process}
        except:
            pass
        
        self.log("تعذر تشغيل خادم Flask", "WARNING")
        return {'status': 'warning'}
    
    def run_all(self):
        """تشغيل جميع الأوامر بالترتيب"""
        self.log("بدء التشغيل التلقائي المتتابع")
        self.log("=" * 50)
        
        # 1. تشغيل خادم Flask
        flask_result = self.run_flask_server()
        self.results['flask_server'] = flask_result
        
        # الانتظار قليلاً بعد تشغيل الخادم
        time.sleep(3)
        
        # 2. تشغيل test_gov.py
        gov_result = self.run_command('python test_gov.py', 'مسح المواقع الحكومية')
        self.results['test_gov'] = gov_result
        
        # 3. تشغيل test_gov_dorks.py
        dorks_result = self.run_command('python test_gov_dorks.py', 'مسح Google Dorks')
        self.results['test_gov_dorks'] = dorks_result
        
        # 4. تشغيل terminal_scan.py
        terminal_result = self.run_command('python terminal_scan.py https://www.gov.il', 'المسح النهائي على التيرمنال')
        self.results['terminal_scan'] = terminal_result
        
        # عرض الملخص النهائي
        self.show_summary()
        
        # حفظ النتائج
        self.save_results()
    
    def show_summary(self):
        """عرض ملخص النتائج"""
        print("\n" + "=" * 60)
        print("📊 ملخص التشغيل التلقائي")
        print("=" * 60)
        
        total_time = datetime.now() - self.start_time
        
        for task, result in self.results.items():
            status = result.get('status', 'unknown')
            if status == 'success':
                print(f"✅ {task}: تم بنجاح")
            elif status == 'error':
                print(f"❌ {task}: فشل")
            elif status == 'timeout':
                print(f"⏰ {task}: انتهى الوقت")
            else:
                print(f"⚠️ {task}: {status}")
        
        print(f"\n⏱️ الوقت الكلي: {total_time}")
        print("📄 تم حفظ جميع النتائج في ملف auto_run_results.json")
    
    def save_results(self):
        """حفظ جميع النتائج"""
        results_file = f'auto_run_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        final_results = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'total_duration': str(datetime.now() - self.start_time),
            'results': self.results
        }
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, ensure_ascii=False, indent=2)
        
        self.log(f"تم حفظ النتائج في: {results_file}")

def main():
    """الدالة الرئيسية"""
    print("🚀 بدء التشغيل التلقائي المتتابع للأداة الأمنية")
    print("=" * 60)
    print("سيتم تشغيل الأوامر بالترتيب التالي:")
    print("1. app.py - خادم Flask")
    print("2. test_gov.py - مسح المواقع الحكومية")
    print("3. test_gov_dorks.py - مسح Google Dorks")
    print("4. terminal_scan.py - المسح النهائي")
    print("=" * 60)
    
    runner = AutoRunner()
    
    try:
        runner.run_all()
    except KeyboardInterrupt:
        print("\n🛑 تم إيقاف التشغيل التلقائي")
    except Exception as e:
        print(f"\n❌ خطأ في التشغيل التلقائي: {e}")

if __name__ == '__main__':
    main()
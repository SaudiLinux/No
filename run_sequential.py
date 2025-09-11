#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
os.environ['PYTHONIOENCODING'] = 'utf-8'

import os
import sys
import time
import subprocess
import json
from datetime import datetime

def run_script(script_name, args=""):
    """تشغيل سكربت مع عرض النتائج"""
    print(f"\n{'='*60}")
    print(f"🚀 تشغيل: {script_name} {args}")
    print(f"{'='*60}")
    
    try:
        # بناء الأمر الكامل
        command = f"python {script_name} {args}".strip()
        
        # تشغيل الأمر
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=os.getcwd()
        )
        
        # عرض النتائج
        if result.stdout:
            print("📤 النتائج:")
            print(result.stdout)
        
        if result.stderr and "InsecureRequestWarning" not in result.stderr:
            print("⚠️ تحذيرات:")
            print(result.stderr)
        
        # حفظ النتائج
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ خطأ في تشغيل {script_name}: {e}")
        return False

def main():
    """الدالة الرئيسية للتشغيل المتتابع"""
    print("🎯 بدء التشغيل التلقائي المتتابع")
    print("سيتم تشغيل جميع الأوامر بالترتيب...")
    
    scripts = [
        ("app.py", ""),                    # 1. خادم Flask
        ("test_gov.py", ""),               # 2. مسح المواقع الحكومية
        ("test_gov_dorks.py", ""),         # 3. مسح Google Dorks
        ("terminal_scan.py", "https://www.gov.il")  # 4. المسح النهائي
    ]
    
    success_count = 0
    total_count = len(scripts)
    
    for script, args in scripts:
        print(f"\n[{success_count+1}/{total_count}] تشغيل {script}...")
        
        if script == "app.py":
            # تشغيل Flask في خلفية
            print("💡 تشغيل Flask في خلفية...")
            subprocess.Popen(f"python {script}", shell=True)
            time.sleep(3)  # انتظار بدء الخادم
            success_count += 1
            print("✅ تم تشغيل Flask")
        else:
            # تشغيل الأوامر الأخرى بشكل متزامن
            if run_script(script, args):
                success_count += 1
                print(f"✅ {script} تم بنجاح")
            else:
                print(f"⚠️ {script} تم مع تحذيرات")
            
        time.sleep(2)  # تأخير بين الأوامر
    
    print(f"\n{'='*60}")
    print(f"📊 الملخص: {success_count}/{total_count} تم بنجاح")
    print(f"{'='*60}")
    print("💾 جميع النتائج محفوظة في ملفات JSON")
    print("🌐 الخادم يعمل على: http://localhost:5000")
    print("🎉 تم إكمال التشغيل التلقائي!")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import requests
import json
import sys

def test_gov_dorks():
    """اختبار موقع gov.il/ar باستخدام Google Dorks"""
    
    print("🎯 اختبار موقع gov.il/ar باستخدام Google Dorks")
    print("=" * 50)
    
    try:
        # إعداد البيانات
        url = 'http://localhost:5000/api/google_dorks/scan'
        data = {
            'target_url': 'https://www.gov.il/ar',
            'categories': [
                'admin_login',
                'admin_directories', 
                'config_files',
                'sensitive_pages'
            ],
            'max_results': 5
        }
        
        print("📋 إعدادات الفحص:")
        print(f"   الموقع المستهدف: {data['target_url']}")
        print(f"   الفئات المختارة: {', '.join(data['categories'])}")
        print(f"   الحد الأقصى للنتائج: {data['max_results']}")
        print()
        
        # إرسال الطلب
        print("🔄 جاري الفحص...")
        response = requests.post(url, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            # عرض النتائج
            print("✅ تم إكمال الفحص بنجاح!")
            print("=" * 50)
            
            # ملخص النتائج
            total_findings = result.get('total_findings', 0)
            risk_score = result.get('risk_score', 0)
            risk_level = result.get('risk_level', 'غير معروف')
            scan_time = result.get('scan_timestamp', 'غير متاح')
            
            print(f"📊 ملخص النتائج:")
            print(f"   إجمالي النتائج: {total_findings}")
            print(f"   درجة الخطورة: {risk_score}/100")
            print(f"   مستوى الخطورة: {risk_level}")
            print(f"   وقت الفحص: {scan_time}")
            print()
            
            # عرض النتائج التفصيلية
            findings = result.get('findings', {})
            if findings:
                print("🔍 النتائج التفصيلية:")
                print("-" * 50)
                
                category_names = {
                    'admin_login': 'صفحات تسجيل الدخول الإدارية',
                    'admin_directories': 'دلائل الإدارة',
                    'config_files': 'ملفات الإعداد',
                    'backup_files': 'ملفات النسخ الاحتياطي',
                    'log_files': 'ملفات السجلات',
                    'open_directories': 'الدلائل المفتوحة',
                    'sensitive_pages': 'الصفحات الحساسة'
                }
                
                for category, items in findings.items():
                    if items:
                        category_name = category_names.get(category, category)
                        print(f"\n📁 {category_name} ({len(items)} نتيجة):")
                        for i, item in enumerate(items, 1):
                            title = item.get('title', 'بدون عنوان')
                            url = item.get('url', 'بدون رابط')
                            description = item.get('description', 'لا يوجد وصف')
                            print(f"   {i}. {title}")
                            print(f"      الرابط: {url}")
                            print(f"      الوصف: {description}")
                            print()
            else:
                print("ℹ️ لم يتم العثور على نتائج في أي فئة")
                
        else:
            print(f"❌ خطأ في الخادم: {response.status_code}")
            print(f"الرد: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ خطأ: تعذر الاتصال بالخادم")
        print("   تأكد من تشغيل التطبيق على http://localhost:5000")
    except requests.exceptions.Timeout:
        print("❌ خطأ: انتهت مهلة الاتصال")
    except Exception as e:
        print(f"❌ خطأ غير متوقع: {str(e)}")
        print(f"نوع الخطأ: {type(e).__name__}")

if __name__ == "__main__":
    test_gov_dorks()
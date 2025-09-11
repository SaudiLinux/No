#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار موقع gov.il/ar للكشف عن الثغرات الأمنية
"""

import json
import urllib.request
import urllib.parse

def test_gov_website():
    """اختبار موقع gov.il/ar"""
    
    url = 'http://localhost:5000/api/exploitation/test'
    
    data = {
        'target_url': 'https://www.gov.il/ar',
        'vulnerability_types': ['sql', 'xss', 'lfi', 'idor'],
        'safe_mode': True
    }
    
    # تحويل البيانات إلى JSON
    json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
    
    # إعداد الطلب
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Accept', 'application/json')
    
    try:
        print("🔄 جاري اختبار موقع gov.il/ar...")
        print(f"📍 الرابط: {data['target_url']}")
        print(f"🔍 أنواع الثغرات: {', '.join(data['vulnerability_types'])}")
        print(f"🛡️  الوضع الآمن: {data['safe_mode']}")
        print("-" * 50)
        
        # إرسال الطلب
        with urllib.request.urlopen(req, json_data) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        if result.get('success'):
            print("✅ تم اكتمال الاختبار بنجاح!")
            print()
            print("📊 الملخص:")
            print(f"  • إجمالي الاختبارات: {result['summary']['total_tests']}")
            print(f"  • الاستغلالات الناجحة: {result['summary']['successful_exploits']}")
            print(f"  • الاختبارات الفاشلة: {result['summary']['failed_tests']}")
            print(f"  • الوضع الآمن: {result['summary']['safe_mode']}")
            
            if result.get('successful_exploits'):
                print()
                print("⚠️  استغلالات ناجحة تم اكتشافها:")
                for exploit in result['successful_exploits']:
                    print(f"    - نوع: {exploit['vulnerability_type']}")
                    print(f"    - مستوى الخطورة: {exploit['risk_level']}")
            else:
                print()
                print("✅ لم يتم اكتشاف ثغرات ناجحة في الوضع الآمن")
                
            # حفظ النتائج
            with open('gov_test_results.json', 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            print()
            print("💾 تم حفظ النتائج في ملف: gov_test_results.json")
            
        else:
            print("❌ خطأ:", result.get('error'))
            
    except Exception as e:
        print("❌ خطأ في الاتصال:", str(e))

if __name__ == '__main__':
    test_gov_website()
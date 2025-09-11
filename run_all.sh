#!/bin/bash

# تعيين اللغة العربية
echo "🚀 بدء التشغيل التلقائي للأداة الأمنية"
echo "==============================================="

# دالة لطباعة الرسائل
echo_message() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# 1. تشغيل خادم Flask في خلفية
echo_message "[1/4] تشغيل خادم Flask..."
nohup python app.py > flask.log 2>&1 &
FLASK_PID=$!
sleep 5

# 2. تشغيل مسح المواقع الحكومية
echo_message "[2/4] تشغيل مسح المواقع الحكومية..."
python test_gov.py
if [ $? -ne 0 ]; then
    echo_message "⚠️ تحذير: test_gov.py لم يكتمل بنجاح"
fi
sleep 2

# 3. تشغيل مسح Google Dorks
echo_message "[3/4] تشغيل مسح Google Dorks..."
python test_gov_dorks.py
if [ $? -ne 0 ]; then
    echo_message "⚠️ تحذير: test_gov_dorks.py لم يكتمل بنجاح"
fi
sleep 2

# 4. تشغيل المسح النهائي
echo_message "[4/4] تشغيل المسح النهائي..."
python terminal_scan.py https://www.gov.il
if [ $? -ne 0 ]; then
    echo_message "⚠️ تحذير: terminal_scan.py لم يكتمل بنجاح"
fi

echo ""
echo "==============================================="
echo "✅ تم إكمال جميع مراحل التشغيل!"
echo "==============================================="
echo "💾 تم حفظ جميع النتائج في ملفات JSON"
echo "🌐 الخادم يعمل على: http://localhost:5000"
echo "📄 سجلات Flask: flask.log"
echo ""

# إبقاء الخادم يعمل
echo "لإيقاف الخادم استخدم: kill $FLASK_PID"
echo "معرف العملية: $FLASK_PID"
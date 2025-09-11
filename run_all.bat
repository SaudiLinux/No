@echo off
title تشغيل الأداة الأمنية المتتابعة
color 0A
echo.
echo ================================================
echo 🚀 بدء التشغيل التلقائي للأداة الأمنية
echo ================================================
echo.

:: 1. تشغيل خادم Flask
echo [1/4] تشغيل خادم Flask...
start /min cmd /k "python app.py & pause"
timeout /t 5 /nobreak >nul

:: 2. تشغيل مسح المواقع الحكومية
echo [2/4] تشغيل مسح المواقع الحكومية...
python test_gov.py
if %errorlevel% neq 0 (
    echo ⚠️ تحذير: test_gov.py لم يكتمل بنجاح
)
timeout /t 2 /nobreak >nul

:: 3. تشغيل مسح Google Dorks
echo [3/4] تشغيل مسح Google Dorks...
python test_gov_dorks.py
if %errorlevel% neq 0 (
    echo ⚠️ تحذير: test_gov_dorks.py لم يكتمل بنجاح
)
timeout /t 2 /nobreak >nul

:: 4. تشغيل المسح النهائي
echo [4/4] تشغيل المسح النهائي...
python terminal_scan.py https://www.gov.il
if %errorlevel% neq 0 (
    echo ⚠️ تحذير: terminal_scan.py لم يكتمل بنجاح
)

echo.
echo ================================================
echo ✅ تم إكمال جميع مراحل التشغيل!
echo ================================================
echo.
echo 💾 تم حفظ جميع النتائج في ملفات JSON
echo 🌐 الخادم يعمل على: http://localhost:5000
echo.
pause
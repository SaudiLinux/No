# دليل النشر الإحترافي لأداة الأمن السيبراني السعودية

## نظرة عامة
هذا الدليل يوضح كيفية نشر أداة الأمن السيبراني السعودية باستخدام خوادم WSGI احترافية مع عكس خلفي لتأمين الأداء والحماية.

## 🚀 خيارات النشر المتاحة

### 1. Docker (مستحسن)
أبسط طريقة للنشر مع جميع التبعيات والإعدادات الأمنية.

```bash
# نشر سريع
docker-compose up --build -d

# عرض السجلات
docker-compose logs -f

# إيقاف الخدمة
docker-compose down
```

### 2. Nginx + Gunicorn
نشر تقليدي مع تحميل متوازن وعكس خلفي.

```bash
# جعل السكربت قابل للتنفيذ
chmod +x deploy.sh

# تشغيل النشر
./deploy.sh

# اختيار الخيار 2 (Nginx + Gunicorn)
```

### 3. Gunicorn المباشر
للتطوير والاختبار السريع.

```bash
# تشغيل مباشر
gunicorn --config gunicorn_config.py wsgi:application
```

## 🔧 ملفات التكوين

### gunicorn_config.py
إعدادات Gunicorn المحسنة للإنتاج:
- عدد العمال = عدد المعالجات × 2 + 1
- حدود الطلبات لمنع تسرب الذاكرة
- تسجيل مفصل للأداء
- إعدادات أمان متقدمة

### nginx.conf
تكوين Nginx مع:
- SSL/TLS قوي
- رؤوس أمان متقدمة
- ضغط Gzip
- حدود معدل الطلبات
- دعم WebSocket
- حظر الملفات الحساسة

### apache.conf
تكوين Apache البديل مع:
- mod_ssl لأمان HTTPS
- mod_headers للرؤوس الأمنية
- mod_deflate للضغط
- mod_proxy للعكس الخلفي

## 🔒 الأمان

### شهادات SSL
```bash
# إنشاء شهادات ذاتية التوقيع للتطوير
openssl req -x509 -newkey rsa:4096 -keyout ssl/saudi-cyber-key.pem -out ssl/saudi-cyber-cert.pem -days 365 -nodes
```

### الرؤوس الأمنية
- `X-Frame-Options`: منع clickjacking
- `X-Content-Type-Options`: منع MIME sniffing
- `X-XSS-Protection`: حماية XSS
- `Strict-Transport-Security`: فرض HTTPS
- `Content-Security-Policy`: منع تنفيذ أكواد ضارة

### حدود المعدل
- Nginx: 10 طلبات/ثانية للـ API
- Apache: 100 طلب/ثانية كحد أقصى

## 📊 الرصد والتتبع

### سجلات التطبيق
- `logs/gunicorn.log`: سجلات Gunicorn
- `logs/nginx/access.log`: سجلات وصول Nginx
- `logs/nginx/error.log`: سجلات أخطاء Nginx

### نقاط النهاية الصحية
- `/health`: فحص صحة التطبيق
- `/metrics`: مقاييس الأداء (إضافية)

## 🔧 الصيانة

### تحديث التطبيق
```bash
# مع Docker
git pull
docker-compose up --build -d

# مع systemd
sudo systemctl restart saudi-cyber-tool
```

### مراقبة الأداء
```bash
# مراقبة استخدام الموارد
docker stats

# مراقبة السجلات
tail -f logs/gunicorn.log
```

## 🌐 الوصول بعد النشر

### عناوين URL
- التطبيق: `http://localhost:5000` (Gunicorn المباشر)
- Nginx: `http://localhost:80`
- HTTPS: `https://localhost:443`

### اختبار النشر
```bash
# اختبار صحة التطبيق
curl http://localhost/health

# اختبار SSL
curl -k https://localhost/
```

## ⚠️ ملاحظات مهمة

1. **تغيير الإعدادات الافتراضية**: قم بتغيير المفاتيح السرية والكلمات المرور قبل النشر
2. **شهادات SSL**: استخدم شهادات SSL صالحة من Let's Encrypt للإنتاج
3. **النظام الأساسي**: هذا النظام مخصص للاستخدام القانوني فقط
4. **التحديثات**: حافظ على تحديث التبعيات بانتظام

## 🆘 استكشاف الأخطاء

### مشاكل شائعة
1. **Port 80 محجوز**: غير منفذ Nginx إلى 8080
2. **مشاكل الأذونات**: تأكد من أن المستخدم لديه صلاحيات الكتابة في logs/
3. **مشاكل SSL**: تحقق من صحة شهادات SSL

### الأوامر المفيدة
```bash
# فحص حالة الخدمات
sudo systemctl status saudi-cyber-tool
sudo systemctl status nginx

# إعادة تشغيل الخدمات
sudo systemctl restart saudi-cyber-tool
sudo systemctl restart nginx
```
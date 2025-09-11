#!/bin/bash

# Saudi Cyber Security Tool Deployment Script
# Professional deployment with WSGI and reverse proxy

echo "🚀 بدء نشر أداة الأمن السيبراني السعودية..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "لا يجب تشغيل هذا السكربت كـ root"
    exit 1
fi

# Check if required tools are installed
check_dependencies() {
    print_status "التحقق من التبعيات..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 غير مثبت"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 غير مثبت"
        exit 1
    fi
    
    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        print_status "Docker مثبت ✓"
    else
        print_warning "Docker غير مثبت - سيتم استخدام التشغيل المباشر"
    fi
    
    # Check Nginx (optional)
    if command -v nginx &> /dev/null; then
        print_status "Nginx مثبت ✓"
    else
        print_warning "Nginx غير مثبت - سيتم استخدام التشغيل المباشر"
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "تثبيت تبعيات Python..."
    pip3 install -r requirements.txt
    pip3 install gunicorn
}

# Generate SSL certificates (self-signed for development)
generate_ssl() {
    print_status "إنشاء شهادات SSL..."
    mkdir -p ssl
    
    if [[ ! -f ssl/saudi-cyber-cert.pem ]]; then
        openssl req -x509 -newkey rsa:4096 -keyout ssl/saudi-cyber-key.pem -out ssl/saudi-cyber-cert.pem -days 365 -nodes -subj "/C=SA/ST=Riyadh/L=Riyadh/O=Saudi-Cyber-Tool/CN=localhost"
        print_status "تم إنشاء شهادات SSL ذاتية التوقيع"
    else
        print_status "شهادات SSL موجودة بالفعل"
    fi
}

# Setup systemd service
setup_systemd() {
    print_status "إعداد خدمة systemd..."
    
    sudo tee /etc/systemd/system/saudi-cyber-tool.service > /dev/null <<EOF
[Unit]
Description=Saudi Cyber Security Tool
After=network.target

[Service]
Type=notify
User=$USER
Group=$USER
WorkingDirectory=$(pwd)
ExecStart=$(which gunicorn) --config gunicorn_config.py wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    print_status "تم إعداد خدمة systemd"
}

# Setup Nginx configuration
setup_nginx() {
    print_status "إعداد Nginx..."
    
    if [[ -f /etc/nginx/sites-available/saudi-cyber-tool ]]; then
        sudo rm /etc/nginx/sites-available/saudi-cyber-tool
    fi
    
    sudo cp nginx.conf /etc/nginx/sites-available/saudi-cyber-tool
    sudo ln -sf /etc/nginx/sites-available/saudi-cyber-tool /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    sudo nginx -t
    
    print_status "تم إعداد Nginx"
}

# Deploy with Docker
deploy_docker() {
    print_status "نشر باستخدام Docker..."
    
    # Build and run with Docker Compose
    docker-compose up --build -d
    
    print_status "تم النشر بنجاح باستخدام Docker"
}

# Deploy with direct Gunicorn
deploy_direct() {
    print_status "نشر مباشر باستخدام Gunicorn..."
    
    # Create logs directory
    mkdir -p logs
    
    # Start Gunicorn
    gunicorn --config gunicorn_config.py wsgi:application --daemon
    
    print_status "تم تشغيل Gunicorn في الخلفية"
}

# Main deployment function
main() {
    print_status "بدء عملية النشر..."
    
    check_dependencies
    install_python_deps
    generate_ssl
    
    echo ""
    echo "اختر طريقة النشر:"
    echo "1. Docker (مستحسن)"
    echo "2. Nginx + Gunicorn"
    echo "3. Gunicorn مباشر"
    echo ""
    
    read -p "أدخل رقم الخيار (1-3): " choice
    
    case $choice in
        1)
            if command -v docker &> /dev/null; then
                deploy_docker
            else
                print_error "Docker غير مثبت"
                exit 1
            fi
            ;;
        2)
            if command -v nginx &> /dev/null; then
                setup_nginx
                setup_systemd
                sudo systemctl start saudi-cyber-tool
                sudo systemctl enable saudi-cyber-tool
                sudo systemctl restart nginx
            else
                print_error "Nginx غير مثبت"
                exit 1
            fi
            ;;
        3)
            deploy_direct
            ;;
        *)
            print_error "اختيار غير صالح"
            exit 1
            ;;
    esac
    
    print_status "✅ تم اكتمال النشر بنجاح!"
    echo ""
    echo "معلومات الوصول:"
    echo "- التطبيق: http://localhost:5000"
    echo "- Nginx: http://localhost:80"
    echo "- HTTPS: https://localhost:443"
    echo ""
    echo "لعرض السجلات:"
    echo "- Docker: docker-compose logs -f"
    echo "- Gunicorn: tail -f logs/gunicorn.log"
    echo "- Nginx: sudo tail -f /var/log/nginx/saudi-cyber-access.log"
}

# Run main function
main "$@"
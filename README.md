<div align="center">

<img src="https://www.google.com/search?q=https://i.imgur.com/vH7a6dJ.png" alt="Proje ikonu" width="120">

Sunucu Log Yöneticisi

Web Tabanlı, Gerçek Zamanlı ve Etkileşimli SSH Log İzleme Platformu

<p>
<img src="https://www.google.com/search?q=https://img.shields.io/badge/S%C3%BCr%C3%BCm-v1.4.0-blue.svg" alt="Sürüm">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Lisans-MIT-green.svg" alt="Lisans">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Backend-Node.js-yellowgreen" alt="Backend">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Frontend-HTML/JS-orange" alt="Frontend">
</p>

</div>

🌟 Proje Hakkında

Sunucu Log Yöneticisi, sunucularınızdaki log dosyalarını bir web arayüzü üzerinden canlı olarak izlemenizi, yönetmenizi ve analiz etmenizi sağlayan modern bir araçtır. Bu proje, sık kullandığınız sunucuları kaydedebileceğiniz kalıcı bir yönetim paneli sunarak, her seferinde bağlantı bilgilerini girme zahmetini ortadan kaldırır. SSH üzerinden güvenli bir şekilde sunucularınıza bağlanır, dosya sisteminde gezinmenize olanak tanır ve seçtiğiniz herhangi bir log dosyasını gerçek zamanlı olarak ekranınıza akıtır.

✨ Temel Özellikler

🧠 Sunucu Yönetim Paneli: Sık kullandığınız sunucuları kaydedin, silin ve tek tıkla bağlanın.

🔒 Güvenli Veritabanı: Sunucu bilgileri Google Firestore üzerinde saklanır ve parolalar AES-256 ile şifrelenir.

📂 Etkileşimli Dosya Gezgini: /var/log ve alt dizinlerinde gezerek izlemek istediğiniz log dosyasını kolayca bulun.

⏳ Geçmiş Logları Yükleme: Canlı akışa geçmeden önce log dosyasının son 200 satırını anında görüntüleyin.

⚡ Canlı Log Akışı: tail -f komutunun gücünü, WebSocket üzerinden anlık olarak web arayüzüne taşır.

🔍 Akıllı Filtreleme ve Vurgulama: Aradığınız kelimeleri log akışı içinde anlık olarak renkli bir şekilde vurgulayın.

📱 Tamamen Duyarlı (Responsive) Arayüz: Telefon, tablet ve masaüstü cihazlarda sorunsuz bir kullanıcı deneyimi sunar.

🎨 Renklendirilmiş Loglar: error, warn, info gibi anahtar kelimelere göre log satırlarını otomatik olarak renklendirir.

🚀 Kurulum

Bu projeyi kendi sunucunuzda çalıştırmak için aşağıdaki adımları izleyin.

Ön Gereksinimler

Node.js: v16 veya üzeri.

npm: Node.js ile birlikte gelir.

Git: Projeyi klonlamak için.

Nginx: Reverse proxy ve SSL için şiddetle tavsiye edilir.

Adım 1: Firebase Kurulumu

Uygulamanın sunucu bilgilerini saklayabilmesi için bir Firestore veritabanına ihtiyacı vardır.

Firebase Console'a gidin ve yeni bir proje oluşturun.

Proje panelinden Firestore Database'i seçin ve test modunda yeni bir veritabanı oluşturun.

Proje Ayarları ⚙️ > Hizmet Hesapları sekmesine gidin.

"Yeni özel anahtar oluştur" butonuna tıklayarak serviceAccountKey.json dosyasını indirin. Bu dosya çok önemlidir ve gizli tutulmalıdır.

Adım 2: Backend Kurulumu

Projeyi Klonlayın:

git clone [https://github.com/KULLANICI-ADINIZ/REPO-ADINIZ.git](https://github.com/KULLANICI-ADINIZ/REPO-ADINIZ.git)
cd REPO-ADINIZ


Anahtar Dosyasını Taşıyın:
Önceki adımda indirdiğiniz serviceAccountKey.json dosyasını projenin log-monitor-backend klasörünün içine taşıyın.

Bağımlılıkları Yükleyin:
log-monitor-backend klasörünün içindeyken aşağıdaki komutu çalıştırın:

npm install


Bu komut, package.json dosyasında listelenen express, ssh2, ws, firebase-admin gibi tüm gerekli kütüphaneleri otomatik olarak yükleyecektir.

Adım 3: Reverse Proxy (Nginx) Kurulumu

Backend'inize HTTPS üzerinden güvenli bir şekilde erişmek ve CORS hatalarını önlemek için Nginx kurmanız gerekmektedir.

Nginx'i Yükleyin:

sudo apt update
sudo apt install nginx


Alan Adı ve SSL:
Backend'iniz için bir subdomain oluşturun (örn: backend.alanadiniz.com) ve bu adrese bir SSL sertifikası alın. (Let's Encrypt ve Certbot tavsiye edilir).

sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d backend.alanadiniz.com


Nginx'i Yapılandırın:
sudo nano /etc/nginx/sites-available/default (veya alan adınıza özel dosya) komutuyla Nginx yapılandırma dosyanızı açın ve ilgili server { ... } bloğunu aşağıdakiyle değiştirin:

server {
    server_name backend.alanadiniz.com; # Kendi alan adınızı yazın

    location / {
        # OPTIONS (preflight) istekleri için CORS yönetimi
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '[https://frontend-alan-adiniz.com](https://frontend-alan-adiniz.com)'; # Frontend adresinizi yazın
            add_header 'Access-Control-Allow-Methods' 'GET, POST, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
            add_header 'Access-Control-Max-Age' 172800;
            return 204;
        }

        # Normal istekler için CORS başlığı
        add_header 'Access-Control-Allow-Origin' '[https://frontend-alan-adiniz.com](https://frontend-alan-adiniz.com)' always;

        # İsteği Node.js uygulamasına yönlendirme
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket bağlantısı için gerekli ayarlar
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Certbot tarafından eklenen SSL ayarları
    listen 443 ssl; 
    ssl_certificate /etc/letsencrypt/live/[backend.alanadiniz.com/fullchain.pem](https://backend.alanadiniz.com/fullchain.pem); 
    ssl_certificate_key /etc/letsencrypt/live/[backend.alanadiniz.com/privkey.pem](https://backend.alanadiniz.com/privkey.pem); 
    include /etc/letsencrypt/options-ssl-nginx.conf; 
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; 
}


Nginx'i Yeniden Başlatın:

sudo nginx -t && sudo systemctl reload nginx


Adım 4: Frontend Kurulumu

log_monitor.html dosyasını web sunucunuzun (frontend'in yayınlandığı yer) kök dizinine taşıyın.

Dosyayı bir metin editörüyle açın ve en üstteki <script> bölümünde yer alan aşağıdaki değişkenleri, Adım 3'te yapılandırdığınız backend adresinizle güncelleyin:

// Backend URL'si
const apiUrl = '[https://backend.alanadiniz.com](https://backend.alanadiniz.com)';
const wsUrl = 'wss://backend.alanadiniz.com';


Adım 5: Uygulamayı Başlatma

Backend'i Başlatın:
log-monitor-backend klasörünün içindeyken:

node server.js

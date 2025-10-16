<div align="center">
<img src="https://www.google.com/search?q=https://i.imgur.com/vH7a6dJ.png" alt="Proje ikonu" width="150">
<h1>Sunucu Log Yöneticisi</h1>
<p>
<b>Web tabanlı, gerçek zamanlı ve etkileşimli SSH log izleme platformu</b>
</p>
<p>
<img src="https://www.google.com/search?q=https://img.shields.io/badge/S%C3%BCr%C3%BCm-v1.4.0-blue.svg" alt="Sürüm">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Lisans-MIT-green.svg" alt="Lisans">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Backend-Node.js-yellowgreen" alt="Backend">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Frontend-Vanilla_JS-orange" alt="Frontend">
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

🛠️ Teknoloji Yığını

Backend: Node.js, Express.js, WebSocket (ws), SSH2, Firebase Admin

Frontend: HTML5, Tailwind CSS, Vanilla JavaScript

Veritabanı: Google Firestore

Proxy & SSL: Nginx, Let's Encrypt

🚀 Kurulum Kılavuzu

Bu projeyi kendi altyapınızda çalıştırmak için aşağıdaki adımları dikkatlice izleyin.

Ön Gereksinimler

Node.js: v16 veya daha güncel bir sürüm.

Nginx: Backend için reverse proxy olarak kullanılacak.

Alan Adları: Backend ve frontend için ayrı alan adları veya subdomain'ler. (Örn: backend.alanadiniz.com, logs.alanadiniz.com)

Adım 1: Firebase Projesi Oluşturma

Uygulamanın sunucu bilgilerini saklayabilmesi için bir Firestore veritabanına ihtiyacımız var.

Firebase Console'a gidin ve yeni bir proje oluşturun.

Proje panelinden Firestore Database'i seçin ve test modunda yeni bir veritabanı oluşturun.

Proje Ayarları ⚙️ > Hizmet Hesapları sekmesine gidin.

"Yeni özel anahtar oluştur" butonuna tıklayarak serviceAccountKey.json dosyasını indirin. Bu dosya, backend'inizin kimliğini doğrulamak için kullanılacak ve gizli tutulmalıdır.

Adım 2: Backend Kurulumu

Projeyi Klonlayın ve Dizine Girin:

git clone [https://github.com/KULLANICI-ADINIZ/REPO-ADINIZ.git](https://github.com/KULLANICI-ADINIZ/REPO-ADINIZ.git)
cd REPO-ADINIZ/log-monitor-backend


Anahtar Dosyasını Taşıyın:
Bir önceki adımda indirdiğiniz serviceAccountKey.json dosyasını şu an içinde bulunduğunuz log-monitor-backend klasörüne taşıyın.

Bağımlılıkları Yükleyin:
npm, package.json dosyasını okuyarak gerekli tüm kütüphaneleri yükleyecektir.

npm install


Adım 3: Reverse Proxy (Nginx) Yapılandırması

Backend'inize HTTPS üzerinden güvenli bir şekilde erişmek ve CORS hatalarını önlemek için Nginx'i yapılandıracağız.

SSL Sertifikası Alın:
Backend alan adınız için Let's Encrypt kullanarak ücretsiz bir SSL sertifikası alın.

sudo apt update
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d backend.alanadiniz.com


Nginx'i Yapılandırın:
sudo nano /etc/nginx/sites-available/default (veya alan adınıza özel dosya) komutuyla Nginx yapılandırma dosyanızı açın ve ilgili server bloğunu aşağıdakiyle değiştirin. (Adresleri kendinize göre düzenlemeyi unutmayın!)

server {
    server_name backend.alanadiniz.com; # 1. Kendi backend alan adınızı yazın

    location / {
        # Tarayıcının ön kontrol (preflight) isteklerini yönetir
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '[https://logs.alanadiniz.com](https://logs.alanadiniz.com)'; # 2. Kendi frontend alan adınızı yazın
            add_header 'Access-Control-Allow-Methods' 'GET, POST, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
            add_header 'Access-Control-Max-Age' 172800;
            return 204;
        }

        # Normal istekler için CORS başlığını ekler
        add_header 'Access-Control-Allow-Origin' '[https://logs.alanadiniz.com](https://logs.alanadiniz.com)' always; # 3. Kendi frontend alan adınızı yazın

        # İsteği Node.js uygulamasına yönlendirir
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket bağlantısının çalışması için gerekli ayarlar
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


Adım 4: Frontend Yapılandırması

Proje ana dizinindeki log_monitor.html dosyasını bir metin editörüyle açın.

<script> bölümünün en başındaki iki değişkeni, kendi backend adresinizle güncelleyin:

// Backend URL'si
const apiUrl = '[https://backend.alanadiniz.com](https://backend.alanadiniz.com)';
const wsUrl = 'wss://backend.alanadiniz.com';


Bu düzenlenmiş log_monitor.html dosyasını, frontend'i yayınlayacağınız sunucunun kök dizinine yükleyin.

Adım 5: Uygulamayı Başlatma

Backend'i Başlatın:
log-monitor-backend klasörünün içindeyken:

node server.js

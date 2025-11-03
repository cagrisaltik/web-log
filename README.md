<div align="center">
<img src="https://img.icons8.com/?size=100&id=krF61fGNbkFk&format=png&color=000000)"  width="150">
<h1>Sunucu Log Yöneticisi</h1>
<p>
<b>Web tabanlı, gerçek zamanlı ve etkileşimli SSH log izleme platformu</b>
</p>
<p>
<img src="https://img.shields.io/badge/S%C3%BCr%C3%BCm-v1.4.0-blue.svg" alt="Sürüm">
<img src="https://img.shields.io/badge/Lisans-MIT-green.svg" alt="Lisans">
<img src="https://img.shields.io/badge/Backend-Node.js-yellowgreen" alt="Backend">
<img src="https://img.shields.io/badge/Frontend-Vanilla_JS-orange" alt="Frontend">
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

Adım 1: Firebase Projesi Oluşturma

Uygulamanın sunucu bilgilerini saklayabilmesi için bir Firestore veritabanına ihtiyacımız var.

Firebase Console'a gidin ve yeni bir proje oluşturun.

Proje panelinden Firestore Database'i seçin ve  yeni bir veritabanı oluşturun.

Proje Ayarları ⚙️ > Hizmet Hesapları sekmesine gidin.

"Yeni özel anahtar oluştur" butonuna tıklayarak serviceAccountKey.json dosyasını indirin. Bu dosya, backend'inizin kimliğini doğrulamak için kullanılacak ve gizli tutulmalıdır.

Adım 2: Backend Kurulumu

Installer'i İndirin:

curl -O https://raw.githubusercontent.com/cagrisaltik/weblog-installer/main/install.weblog.sh

Installer dosyasına çalıştırma izni verin

chmod +x install.weblog.sh

Daha öncesinde indirmiş olduğunuz serviceAccountKey.json dosyası ile install.weblog.sh dosyasını aynı dizinde bulundurun.

./ İle scripti çalıştırıp kurulum sırasında sizlerden istenilen bilgileri giriniz.

 ./install.weblog.sh


Adım 3 : Kurulumda bir sorun ile karşılaşılmaması halinde frontend yayına başlayacak. Backend ise Screen içerisinde çalışır durumda olacaktır.



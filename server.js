const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const path = require('path');
const crypto = require('crypto');
const admin = require('firebase-admin');

// --- Firebase'i Başlatma ---
// serviceAccountKey.json dosyasının bu dosya ile aynı dizinde olduğundan emin olun
try {
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
} catch (error) {
    console.error("Firebase Admin SDK başlatılamadı! serviceAccountKey.json dosyasını kontrol edin.", error);
    process.exit(1); // Hata durumunda uygulamayı durdur
}
const db = admin.firestore();
const serversCollection = db.collection('servers');
// ------------------------------------

// --- Parola Şifreleme Altyapısı ---
const algorithm = 'aes-256-cbc';
// GERÇEK UYGULAMADA BU DEĞERLERİ GÜVENLİ BİR YERDEN (ORTAM DEĞİŞKENİ VB.) ALIN!
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'a1b2c3d4e5f6g7h8a1b2c3d4e5f6g7h8'; // 32 byte olmalı
const IV_LENGTH = 16;
// ------------------------------------------

const app = express();
app.use(express.json()); // JSON body'lerini parse etmek için
const PORT = process.env.PORT || 3000; // Ortam değişkeninden port al, yoksa 3000 kullan

let sshConnection = null;
let activeLogStream = null;

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const BASE_LOG_DIR = '/var/log'; // Logların aranacağı ana dizin

// --- Şifreleme ve Çözme Fonksiyonları ---
function encrypt(text) {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY), iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error("Şifreleme hatası:", error);
        throw new Error("Şifreleme sırasında bir hata oluştu.");
    }
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        if (textParts.length !== 2) throw new Error("Geçersiz şifrelenmiş metin formatı.");
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error("Şifre çözme hatası:", error);
        throw new Error("Şifre çözme sırasında bir hata oluştu.");
    }
}

// --- API Endpoint'leri ---

// Ana endpoint (test için)
app.get('/', (req, res) => res.send('Backend sunucusu çalışıyor!'));

// Kayıtlı sunucuları listeler
app.get('/servers', async (req, res) => {
    try {
        const snapshot = await serversCollection.get();
        const servers = [];
        snapshot.forEach(doc => {
            const serverData = doc.data();
            delete serverData.password; // Hassas veriyi gönderme
            delete serverData.privateKey; // Hassas veriyi gönderme
            servers.push({ id: doc.id, ...serverData });
        });
        res.json({ success: true, servers });
    } catch (error) {
        console.error("Sunucuları listeleme hatası:", error);
        res.status(500).json({ success: false, message: 'Sunucular listelenemedi.' });
    }
});

// Yeni bir sunucu ekler
app.post('/servers', async (req, res) => {
    try {
        const { name, ip, user, port, authType, pass, privateKey } = req.body;
        // Gerekli alan kontrolü
        if (!name || !ip || !user || !authType) {
            return res.status(400).json({ success: false, message: 'İsim, IP, Kullanıcı Adı ve Kimlik Doğrulama Tipi zorunludur.' });
        }
        
        const serverPort = parseInt(port, 10) || 22; // Port'u sayıya çevir, yoksa 22 kullan
        if (isNaN(serverPort) || serverPort <= 0 || serverPort > 65535) {
             return res.status(400).json({ success: false, message: 'Geçersiz port numarası.' });
        }

        const newServer = { name, ip, user, port: serverPort, authType };

        // Kimlik doğrulama bilgisine göre şifreleme
        if (authType === 'password') {
            if (!pass) return res.status(400).json({ success: false, message: 'Parola gereklidir.' });
            newServer.password = encrypt(pass);
        } else if (authType === 'key') {
            if (!privateKey) return res.status(400).json({ success: false, message: 'Özel anahtar gereklidir.' });
            newServer.privateKey = encrypt(privateKey);
        } else {
            return res.status(400).json({ success: false, message: 'Geçersiz kimlik doğrulama tipi.' });
        }
        
        // Firestore'a ekleme
        const docRef = await serversCollection.add(newServer);
        res.status(201).json({ success: true, id: docRef.id, message: 'Sunucu başarıyla eklendi.' });
    } catch (error) {
        console.error("Sunucu ekleme hatası:", error);
        res.status(500).json({ success: false, message: `Sunucu eklenemedi: ${error.message}` });
    }
});

// Bir sunucuyu siler
app.delete('/servers/:id', async (req, res) => {
    try {
        const serverId = req.params.id;
        const docRef = serversCollection.doc(serverId);
        const doc = await docRef.get();

        if (!doc.exists) {
            return res.status(404).json({ success: false, message: 'Silinecek sunucu bulunamadı.' });
        }

        await docRef.delete();
        res.json({ success: true, message: 'Sunucu başarıyla silindi.' });
    } catch (error) {
        console.error("Sunucu silme hatası:", error);
        res.status(500).json({ success: false, message: 'Sunucu silinemedi.' });
    }
});

// Belirtilen ID'deki sunucuya bağlanır
app.post('/connect', async (req, res) => {
    // Mevcut bağlantı varsa kapat
    if (sshConnection) {
        try {
            sshConnection.end();
        } catch (e) { console.error("Mevcut SSH bağlantısı kapatılırken hata:", e); }
        sshConnection = null;
    }

    try {
        const { serverId } = req.body;
        if (!serverId) return res.status(400).json({ success: false, message: 'Sunucu ID bilgisi eksik.' });

        // Firestore'dan sunucu bilgilerini al
        const serverDoc = await serversCollection.doc(serverId).get();
        if (!serverDoc.exists) return res.status(404).json({ success: false, message: 'Sunucu bulunamadı.' });
        
        const serverData = serverDoc.data();
        
        // Bağlantı konfigürasyonunu oluştur
        const connectionConfig = {
            host: serverData.ip,
            port: serverData.port || 22,
            username: serverData.user,
            readyTimeout: 20000 // 20 saniye bağlantı timeout
        };

        // Kimlik doğrulama yöntemine göre bilgileri ekle (ve çöz)
        if (serverData.authType === 'key' && serverData.privateKey) {
            connectionConfig.privateKey = decrypt(serverData.privateKey);
        } else if ((serverData.authType === 'password' || !serverData.authType) && serverData.password) { // Eski kayıtlarla uyumluluk
            connectionConfig.password = decrypt(serverData.password);
        } else {
            return res.status(400).json({ success: false, message: 'Sunucu için geçerli kimlik doğrulama metodu bulunamadı.' });
        }

        // Yeni SSH bağlantısı oluştur
        const conn = new Client();
        conn.on('ready', () => {
            console.log(`SSH Bağlantısı Başarılı: ${serverData.ip}`);
            sshConnection = conn; // Bağlantıyı global değişkende sakla
            res.json({ success: true, message: 'Sunucuya başarıyla bağlanıldı!', ip: serverData.ip });
        }).on('error', (err) => {
            console.error(`SSH Bağlantı Hatası (${serverData.ip}):`, err.message);
            // Daha anlaşılır hata mesajları
            let userMessage = `Bağlantı hatası: ${err.message}`;
            if (err.message.includes('authentication methods failed')) {
                userMessage = 'Kimlik doğrulama başarısız. Kullanıcı adı, parola veya özel anahtarınızı kontrol edin.';
            } else if (err.message.includes('ECONNREFUSED')) {
                userMessage = 'Bağlantı reddedildi. Sunucu IP veya port numarasını kontrol edin, SSH servisinin çalıştığından emin olun.';
            } else if (err.message.includes('ETIMEDOUT') || err.message.includes('Timed out')) {
                userMessage = 'Bağlantı zaman aşımına uğradı. Sunucu IP veya port numarasını kontrol edin, ağ bağlantınızı veya güvenlik duvarı ayarlarını gözden geçirin.';
            }
             // Bağlantı nesnesini temizle
            try { conn.end(); } catch (e) {}
            sshConnection = null;
            res.status(500).json({ success: false, message: userMessage });
        }).connect(connectionConfig);

        // Bağlantı kapatıldığında global değişkeni temizle
        conn.on('close', () => {
             console.log(`SSH Bağlantısı Kapatıldı: ${serverData.ip}`);
             if (sshConnection === conn) { // Sadece bu bağlantı ise temizle
                 sshConnection = null;
             }
        });

    } catch (error) {
        console.error("Bağlantı işlemi sırasında genel hata:", error);
        res.status(500).json({ success: false, message: `Bağlanırken bir hata oluştu: ${error.message}` });
    }
});

// Sunucunun anlık durumunu (uptime, disk, ram, cpu) getirir
app.get('/server-status', (req, res) => {
    if (!sshConnection) {
        return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
    }

    // SSH üzerinden komut çalıştırmak için yardımcı fonksiyon
    const executeCommand = (command) => new Promise((resolve, reject) => {
        if (!sshConnection) return reject(new Error('SSH bağlantısı mevcut değil.'));
        sshConnection.exec(command, (err, stream) => {
            if (err) return reject(err);
            let data = '';
            let errorData = '';
            stream.on('data', chunk => data += chunk.toString())
                  .stderr.on('data', errChunk => errorData += errChunk.toString())
                  .on('close', (code) => {
                      if (code !== 0) { // Komut hata ile bittiyse
                          reject(new Error(errorData.trim() || `Komut '${command}' hata kodu ${code} ile bitti.`));
                      } else {
                          resolve(data.trim());
                      }
                  });
        });
    });

    // Gerekli komutları paralel olarak çalıştır
    Promise.all([
        executeCommand('uptime -p'),
        executeCommand("df -h / | awk 'NR==2{print $2,$3,$5}'"), // Total, Used, Percent for root '/'
        executeCommand("free -m | awk 'NR==2{print $2,$3}'"), // Total, Used memory in MB
        executeCommand("top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'") // CPU Usage %
    ]).then(([uptimeOutput, diskOutput, memOutput, cpuOutput]) => {
        
        // Komut çıktılarını parse et
        const diskParts = diskOutput.split(' ');
        const memParts = memOutput.split(' ');
        
        const memoryUsed = parseInt(memParts[1], 10) || 0;
        const memoryTotal = parseInt(memParts[0], 10) || 0;
        const memoryPercent = memoryTotal > 0 ? Math.round((memoryUsed / memoryTotal) * 100) : 0;
        
        const cpuPercent = parseFloat(cpuOutput).toFixed(1) || '0.0';

        // Sonucu JSON olarak hazırla
        const status = {
            uptime: uptimeOutput.replace('up ', ''),
            disk: {
                total: diskParts[0] || 'N/A',
                used: diskParts[1] || 'N/A',
                percent: diskParts[2] || 'N/A'
            },
            memory: {
                total: `${memoryTotal}MB`,
                used: `${memoryUsed}MB`,
                percent: `${memoryPercent}%`
            },
            cpu: {
                percent: `${cpuPercent}%`
            }
        };

        res.json({ success: true, status });

    }).catch(error => {
        console.error("Sunucu durumu alınırken hata:", error.message);
        res.status(500).json({ success: false, message: `Sunucu durumu alınamadı: ${error.message}` });
    });
});

// Belirtilen dizindeki dosya ve klasörleri listeler
app.post('/browse', (req, res) => {
    if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });

    const requestedSubPath = req.body.path || '/';
    // Güvenlik: Yolu BASE_LOG_DIR ile birleştir ve normalize et
    const fullPath = path.normalize(path.join(BASE_LOG_DIR, requestedSubPath));

    // Güvenlik Kontrolü: Kullanıcının BASE_LOG_DIR dışına çıkmasını engelle
    if (!fullPath.startsWith(path.normalize(BASE_LOG_DIR))) {
        return res.status(403).json({ success: false, message: 'Erişim engellendi.' });
    }

    // ls komutunu -F parametresi ile çalıştır (tipleri belirtir: / klasör, * çalıştırılabilir vb.)
    const command = `ls -F "${fullPath}"`; // Yolu tırnak içine alarak boşluklu isimleri destekle
    sshConnection.exec(command, (err, stream) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        let data = '';
        let errorData = '';
        stream.on('data', (c) => data += c.toString())
              .stderr.on('data', (c) => errorData += c.toString())
              .on('close', (code) => {
                  if (code !== 0) {
                      // Hata varsa, özellikle "No such file or directory" gibi, bunu kullanıcıya bildir
                      return res.status(500).json({ success: false, message: errorData.trim() || `Dizin listelenemedi (hata kodu: ${code}).` });
                  }
                  // Çıktıyı satırlara böl, boş satırları at
                  const items = data.split('\n').filter(Boolean).map(item => ({
                      name: item,
                      // Son karakter '/' ise klasör, değilse dosya olarak işaretle
                      type: item.endsWith('/') ? 'directory' : 'file'
                  }));
                  res.json({ success: true, items: items });
              });
    });
});

// Belirtilen dosyanın son X satırını getirir
app.post('/history', (req, res) => {
    if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });

    const { filePath, lines = 200 } = req.body; // Varsayılan 200 satır
    const absolutePath = path.resolve(filePath);

    // Güvenlik Kontrolü
    if (!absolutePath.startsWith(path.resolve(BASE_LOG_DIR))) {
        return res.status(403).json({ success: false, message: 'Erişim engellendi.' });
    }

    const command = `tail -n ${lines} "${absolutePath}"`; // Yolu tırnak içine al
    sshConnection.exec(command, (err, stream) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        let data = '';
        let errorData = '';
        stream.on('data', (c) => data += c.toString())
              .stderr.on('data', (c) => errorData += c.toString())
              .on('close', (code) => {
                   if (code !== 0 && !data) { // Hata kodu varsa VE hiç data gelmediyse (örn. dosya yok)
                       return res.status(500).json({ success: false, message: errorData.trim() || `Geçmiş loglar alınamadı (hata kodu: ${code}).` });
                   }
                   // Hata olsa bile gelen datayı gönder (örn. tail: file truncated)
                   res.json({ success: true, history: data.split('\n').filter(Boolean) });
               });
    });
});

// Aktif SSH bağlantısını sonlandırır
app.post('/disconnect', (req, res) => {
    if (sshConnection) {
        try {
            sshConnection.end();
        } catch(e) { console.error("Disconnect sırasında SSH bağlantısı kapatılırken hata:", e); }
        sshConnection = null;
    }
    // Aktif log stream'ini de durdur
    if (activeLogStream) {
        try {
            activeLogStream.close(); // Bu ssh2 stream objesi için doğru metod olmayabilir, kontrol et
        } catch(e) { console.error("Disconnect sırasında log stream kapatılırken hata:", e); }
        activeLogStream = null;
    }
    console.log("Bağlantı kesildi (manuel).");
    res.json({ success: true, message: 'Bağlantı başarıyla sonlandırıldı.' });
});

// --- WebSocket Bağlantı Yönetimi ---
wss.on('connection', ws => {
    console.log('Yeni bir WebSocket istemcisi bağlandı.');
    let currentStream = null; // Her WebSocket bağlantısı için kendi stream'ini tut

    // İstemciden mesaj geldiğinde (izlenecek dosya yolu)
    ws.on('message', message => {
        const filePath = message.toString();
        console.log(`İzleme isteği alındı: ${filePath}`);

        // Önceki stream'i (varsa) kapat
        if (currentStream) {
            try { currentStream.close(); } catch (e) {}
            currentStream = null;
        }
        // Global sshConnection yoksa hata gönder
        if (!sshConnection) return ws.send('[SYSTEM] Hata: Aktif SSH bağlantısı yok.');

        // Güvenlik Kontrolü
        const fullPath = path.resolve(filePath);
        if (!fullPath.startsWith(path.resolve(BASE_LOG_DIR))) return ws.send('[SYSTEM] Hata: Erişim engellendi.');

        // `tail -f` komutunu çalıştır
        const command = `tail -f "${fullPath}"`;
        sshConnection.exec(command, (err, stream) => {
            if (err) return ws.send(`[SYSTEM] Hata: ${err.message}`);

            console.log(`'${filePath}' için tail -f başlatıldı.`);
            currentStream = stream; // Bu WebSocket için stream'i sakla

            // Yeni veri geldiğinde istemciye gönder
            stream.on('data', data => {
                if (ws.readyState === WebSocket.OPEN) { // Sadece bağlantı açıksa gönder
                    ws.send(data.toString());
                }
            })
            // Hata çıktısı olursa istemciye gönder
            .stderr.on('data', data => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(`[SYSTEM] Hata: ${data.toString()}`);
                }
            })
            // Stream kapandığında (örn. dosya silindiğinde)
            .on('close', () => {
                 console.log(`'${filePath}' için tail -f sonlandı.`);
                 if (currentStream === stream) { // Sadece bu stream ise temizle
                     currentStream = null;
                 }
                 if (ws.readyState === WebSocket.OPEN) {
                    ws.send('[SYSTEM] Log akışı sonlandı.');
                 }
            });
        });
    });

    // WebSocket bağlantısı kapandığında
    ws.on('close', () => {
        console.log('WebSocket istemcisi ayrıldı.');
        // İlgili stream'i kapat
        if (currentStream) {
            try { currentStream.close(); } catch (e) {}
            currentStream = null;
        }
    });

    // WebSocket hatası oluştuğunda
    ws.on('error', (error) => {
        console.error('WebSocket hatası:', error);
        if (currentStream) {
            try { currentStream.close(); } catch (e) {}
            currentStream = null;
        }
    });
});

// Sunucuyu başlat
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde başlatıldı.`);
});

// Uygulama kapanırken SSH bağlantısını düzgünce kapat
process.on('SIGINT', () => {
    console.log("Uygulama kapatılıyor...");
    if (sshConnection) {
        sshConnection.end();
    }
    server.close(() => {
        console.log("HTTP sunucusu kapatıldı.");
        process.exit(0);
    });
});


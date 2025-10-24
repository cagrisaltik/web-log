const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const path = require('path');
const crypto = require('crypto');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer'); // YENİ: E-posta için
const axios = require('axios'); // YENİ: Webhook için

// --- Firebase'i Başlatma ---
try {
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
} catch (error) {
    console.error("Firebase Admin SDK başlatılamadı! serviceAccountKey.json dosyasını kontrol edin.", error);
    process.exit(1); // Hata durumunda uygulamayı durdur
}
const db = admin.firestore();
const serversCollection = db.collection('servers');
const settingsCollection = db.collection('settings'); // YENİ: Ayarlar için
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
// YENİ: Aktif stream'leri ve ayarları saklamak için daha gelişmiş bir yapı
let activeStreams = new Map(); // ws -> { stream, serverId, filePath }

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const BASE_LOG_DIR = '/var/log'; // Logların aranacağı ana dizin

// --- Şifreleme ve Çözme Fonksiyonları ---
function encrypt(text) {
    try {
        if (!text) return null; // Boş metni şifreleme
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
        if (!text) return null; // Boş metni çözme
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

// executeCommand - exit ve close olaylarını birlikte ele alır
const executeCommand = (command) => new Promise((resolve, reject) => {
    if (!sshConnection) return reject(new Error('SSH bağlantısı mevcut değil.'));

    let stdoutData = '';
    let stderrData = '';
    let exitCode = null;
    let exitSignal = null;
    let streamClosed = false;

    console.log(`[DEBUG] Komut çalıştırılıyor: ${command}`);

    sshConnection.exec(command, (err, stream) => {
        if (err) {
            console.error(`[DEBUG] Komut başlatılamadı (${command}):`, err);
            return reject(new Error(`Komut başlatılamadı (${command}): ${err.message}`));
        }

        console.log(`[DEBUG] Stream oluşturuldu (${command}). Olaylar dinleniyor...`);

        stream.on('data', chunk => { stdoutData += chunk.toString(); })
        .stderr.on('data', errChunk => { console.log(`[DEBUG] stderr (${command}): Veri alındı (${errChunk.length} byte)`); stderrData += errChunk.toString(); })
        .on('exit', (code, signal) => { console.log(`[DEBUG] Komut '${command}' exit olayı. Kod: ${code}, Sinyal: ${signal}`); exitCode = code; exitSignal = signal; })
        .on('close', () => {
             console.log(`[DEBUG] Stream '${command}' close olayı. Stderr: '${stderrData.trim()}'`);
             streamClosed = true;

             if (stderrData.trim()) {
                  console.warn(`[DEBUG] Komut '${command}' stderr üretti: ${stderrData.trim()}`);
                  // ls için spesifik hataları direkt ilet, diğer durumlarda exit koduna bak
                  if (command.startsWith('ls') && (stderrData.includes('Permission denied') || stderrData.includes('No such file or directory'))) {
                      reject(new Error(stderrData.trim()));
                  } else if (exitCode === 0) {
                      // Bazen stderr'e bilgi yazılır ama kod 0'dır, bunu başarılı sayalım
                      console.log(`[DEBUG] Komut '${command}' stderr üretti ama exit kodu 0, başarılı kabul ediliyor.`);
                      resolve(stdoutData.trim());
                  } else {
                     reject(new Error(stderrData.trim())); // Diğer stderr hataları
                  }
             }
             else if (exitCode === 0) {
                 console.log(`[DEBUG] Komut '${command}' başarılı (exit kodu 0).`);
                 resolve(stdoutData.trim());
             }
             else if (exitCode !== null && exitCode !== 0) {
                  const exitInfo = `çıkış kodu ${exitCode}`;
                  console.error(`[DEBUG] Komut '${command}' başarısız oldu: ${exitInfo}`);
                  reject(new Error(`Komut '${command}' ${exitInfo}.`));
             }
             else { // stderr yok, exit kodu belirsiz -> Başarılı kabul et (güvenilir olmayan durumlar için)
                  console.log(`[DEBUG] Komut '${command}' başarılı (close olayı, stderr boş, exit kodu belirsiz).`);
                  resolve(stdoutData.trim());
             }
        })
        .on('error', (streamErr) => {
           console.error(`[DEBUG] Stream hatası (${command}):`, streamErr);
           if (!streamClosed) reject(new Error(`Stream hatası (${command}): ${streamErr.message}`));
        });
    });
});


// /proc/stat'tan CPU zamanlarını parse eden fonksiyon
const parseProcStat = (statOutput) => {
    const lines = statOutput.split('\n'); const cpuLine = lines.find(line => line.startsWith('cpu ')); if (!cpuLine) return null;
    const times = cpuLine.split(/\s+/).slice(1).map(Number); if (times.length < 4) return null; // En az user, nice, system, idle olmalı
    const idle = times[3] || 0; const total = times.reduce((sum, time) => sum + time, 0); return { idle, total };
};
// /proc/stat'ı iki kez okuyup CPU kullanımını hesaplayan fonksiyon
const getCpuUsage = () => new Promise(async (resolve, reject) => {
    try {
        console.log("[DEBUG] getCpuUsage başlatıldı.");
        const stat1Output = await executeCommand('cat /proc/stat'); const stat1 = parseProcStat(stat1Output);
        if (!stat1) { console.error("[DEBUG] /proc/stat formatı anlaşılamadı (ilk okuma)."); return reject(new Error("/proc/stat formatı anlaşılamadı (ilk okuma).")); }
        console.log("[DEBUG] İlk /proc/stat okundu.");
        await new Promise(res => setTimeout(res, 500)); // Arada bekleme süresi
        console.log("[DEBUG] İkinci /proc/stat okunuyor...");
        const stat2Output = await executeCommand('cat /proc/stat'); const stat2 = parseProcStat(stat2Output);
        if (!stat2) { console.error("[DEBUG] /proc/stat formatı anlaşılamadı (ikinci okuma)."); return reject(new Error("/proc/stat formatı anlaşılamadı (ikinci okuma).")); }
        console.log("[DEBUG] İkinci /proc/stat okundu.");
        const idleDiff = stat2.idle - stat1.idle; const totalDiff = stat2.total - stat1.total;
        // Zaman farkı yoksa veya negatifse (çok nadir bir durum, sistem saatiyle oynanmış olabilir)
        if (totalDiff <= 0) { console.log("[DEBUG] CPU zaman farkı <= 0, %0 kullanım varsayılıyor."); resolve("0.0"); return; }
        const usage = 100 * (1 - idleDiff / totalDiff); // Hesaplama
        console.log(`[DEBUG] CPU kullanımı hesaplandı: ${usage.toFixed(1)}%`); resolve(usage.toFixed(1));
    } catch (error) { console.error("[DEBUG] getCpuUsage içinde hata:", error); reject(error); } // Hataları yakala ve ilet
});

// --- API Endpoint'leri ---
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

// Sunucu bilgilerini güncelleyen endpoint
app.put('/servers/:id', async (req, res) => {
    try {
        const serverId = req.params.id;
        const { name, ip, user, port, authType, pass, privateKey } = req.body;

        if (!name || !ip || !user || !authType) return res.status(400).json({ success: false, message: 'İsim, IP, Kullanıcı Adı ve Kimlik Doğrulama Tipi zorunludur.' });
        const serverPort = parseInt(port, 10) || 22;
        if (isNaN(serverPort) || serverPort <= 0 || serverPort > 65535) return res.status(400).json({ success: false, message: 'Geçersiz port numarası.' });

        const docRef = serversCollection.doc(serverId);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ success: false, message: 'Güncellenecek sunucu bulunamadı.' });

        const updatedServer = { name, ip, user, port: serverPort, authType };

        if (authType === 'password') {
            if (pass) { // Sadece yeni parola varsa güncelle
                updatedServer.password = encrypt(pass);
                updatedServer.privateKey = admin.firestore.FieldValue.delete();
            } else if (doc.data().authType === 'key') { // Auth tipi değiştiyse eski anahtarı sil
                 updatedServer.privateKey = admin.firestore.FieldValue.delete();
            }
        } else if (authType === 'key') {
            if (privateKey) { // Sadece yeni anahtar varsa güncelle
                updatedServer.privateKey = encrypt(privateKey);
                updatedServer.password = admin.firestore.FieldValue.delete();
            } else if (doc.data().authType === 'password') { // Auth tipi değiştiyse eski parolayı sil
                 updatedServer.password = admin.firestore.FieldValue.delete();
            }
        } else {
            return res.status(400).json({ success: false, message: 'Geçersiz kimlik doğrulama tipi.' });
        }

        await docRef.update(updatedServer);
        res.json({ success: true, message: 'Sunucu başarıyla güncellendi.' });

    } catch (error) {
        console.error("Sunucu güncelleme hatası:", error);
        res.status(500).json({ success: false, message: `Sunucu güncellenemedi: ${error.message}` });
    }
});

// Bir sunucuyu siler
app.delete('/servers/:id', async (req, res) => {
    try {
        const serverId = req.params.id;
        const docRef = serversCollection.doc(serverId);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ success: false, message: 'Silinecek sunucu bulunamadı.' });
        
        await docRef.delete();
        // İlgili ayarları da sil
        await settingsCollection.doc(serverId).delete().catch(e => console.warn(`Ayarlar silinemedi (zaten olmayabilir): ${e.message}`));
        
        res.json({ success: true, message: 'Sunucu başarıyla silindi.' });
    } catch (error) {
        console.error("Sunucu silme hatası:", error);
        res.status(500).json({ success: false, message: 'Sunucu silinemedi.' });
    }
});

// Belirtilen ID'deki sunucuya bağlanır
app.post('/connect', async (req, res) => {
    if (sshConnection) {
        try { sshConnection.end(); } catch (e) { console.error("Mevcut SSH bağlantısı kapatılırken hata:", e); }
        sshConnection = null;
    }
    try {
        const { serverId } = req.body;
        if (!serverId) return res.status(400).json({ success: false, message: 'Sunucu ID bilgisi eksik.' });
        const serverDoc = await serversCollection.doc(serverId).get();
        if (!serverDoc.exists) return res.status(404).json({ success: false, message: 'Sunucu bulunamadı.' });
        const serverData = serverDoc.data();
        const connectionConfig = { host: serverData.ip, port: serverData.port || 22, username: serverData.user, readyTimeout: 20000 };
        // Geriye dönük uyumluluk ve authType kontrolü
        if (serverData.authType === 'key' && serverData.privateKey) {
            connectionConfig.privateKey = decrypt(serverData.privateKey);
        } else if ((serverData.authType === 'password' || !serverData.authType) && serverData.password) {
            connectionConfig.password = decrypt(serverData.password);
        } else {
            return res.status(400).json({ success: false, message: 'Sunucu için geçerli kimlik doğrulama metodu bulunamadı.' });
        }
        const conn = new Client();
        conn.on('ready', () => {
            console.log(`SSH Bağlantısı Başarılı: ${serverData.ip}`);
            sshConnection = conn;
            res.json({ success: true, message: 'Sunucuya başarıyla bağlanıldı!', ip: serverData.ip });
        }).on('error', (err) => {
            console.error(`SSH Bağlantı Hatası (${serverData.ip}):`, err.message);
            let userMessage = `Bağlantı hatası: ${err.message}`;
            if (err.message.includes('authentication methods failed')) userMessage = 'Kimlik doğrulama başarısız. Kullanıcı adı, parola veya özel anahtarınızı kontrol edin.';
            else if (err.message.includes('ECONNREFUSED')) userMessage = 'Bağlantı reddedildi. Sunucu IP veya port numarasını kontrol edin, SSH servisinin çalıştığından emin olun.';
            else if (err.message.includes('ETIMEDOUT') || err.message.includes('Timed out')) userMessage = 'Bağlantı zaman aşımına uğradı. Sunucu IP veya port numarasını kontrol edin, ağ bağlantınızı veya güvenlik duvarı ayarlarını gözden geçirin.';
            try { conn.end(); } catch (e) {} sshConnection = null;
            res.status(500).json({ success: false, message: userMessage });
        }).connect(connectionConfig);
        conn.on('close', () => {
            console.log(`SSH Bağlantısı Kapatıldı: ${serverData.ip}`);
            if (sshConnection === conn) sshConnection = null;
        });
    } catch (error) {
        console.error("Bağlantı işlemi sırasında genel hata:", error);
        res.status(500).json({ success: false, message: `Bağlanırken bir hata oluştu: ${error.message}` });
    }
});

// Sunucunun anlık durumunu getirir
app.get('/server-status', async (req, res) => {
    if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
    try {
        const uptimePromise = executeCommand('uptime -p').catch(e => "N/A");
        const diskPromise = executeCommand("df -h / | awk 'NR==2{print $2,$3,$5}'").catch(e => "N/A N/A N/A");
        const memPromise = executeCommand("free -m | awk 'NR==2{print $2,$3}'").catch(e => "0 0");
        const cpuPromise = getCpuUsage().catch(e => "0.0");
        const [uptimeOutput, diskOutput, memOutput, cpuOutput] = await Promise.all([uptimePromise, diskPromise, memPromise, cpuPromise]);
        const diskParts = diskOutput.split(' '); const memParts = memOutput.split(' ');
        const memoryUsed = parseInt(memParts[1], 10) || 0; const memoryTotal = parseInt(memParts[0], 10) || 0; const memoryPercent = memoryTotal > 0 ? Math.round((memoryUsed / memoryTotal) * 100) : 0;
        const cpuPercent = parseFloat(cpuOutput).toFixed(1) || '0.0';
        const status = {
            uptime: uptimeOutput !== "N/A" ? uptimeOutput.replace('up ', '') : "N/A",
            disk: { total: diskParts[0] || 'N/A', used: diskParts[1] || 'N/A', percent: diskParts[2] || 'N/A' },
            memory: { total: `${memoryTotal}MB`, used: `${memoryUsed}MB`, percent: `${memoryPercent}%` },
            cpu: { percent: `${cpuPercent}%` }
        };
        res.json({ success: true, status });
    } catch (error) { console.error("[DEBUG] /server-status içinde beklenmedik hata:", error); res.status(500).json({ success: false, message: `Sunucu durumu alınamadı: ${error.message}` }); }
});


// Belirtilen dizindeki dosya ve klasörleri listeler
app.post('/browse', async (req, res) => {
    if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
    const requestedSubPath = req.body.path || '/';
    const fullPath = path.normalize(path.join(BASE_LOG_DIR, requestedSubPath));
    if (!fullPath.startsWith(path.normalize(BASE_LOG_DIR))) return res.status(403).json({ success: false, message: 'Erişim engellendi.' });
    const command = `ls -F "${fullPath}"`;
    try {
        const data = await executeCommand(command);
        const items = data.split('\n').filter(Boolean).map(item => ({ name: item, type: item.endsWith('/') ? 'directory' : 'file' }));
        res.json({ success: true, items: items });
    } catch (error) {
        console.error(`[Browse] Dizin listeleme hatası (${fullPath}):`, error.message);
        let userMessage = `Dizin listelenemedi: ${error.message}`;
        if (error.message.includes('No such file or directory')) userMessage = 'Belirtilen dizin bulunamadı.';
        else if (error.message.includes('Permission denied')) userMessage = 'Bu dizini listelemek için izniniz yok.';
        res.status(500).json({ success: false, message: userMessage });
    }
});
// Belirtilen dosyanın son X satırını getirir
app.post('/history', (req, res) => {
    if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
    const { filePath, lines = 200 } = req.body;
    const absolutePath = path.resolve(filePath);
    if (!absolutePath.startsWith(path.resolve(BASE_LOG_DIR))) { return res.status(403).json({ success: false, message: 'Erişim engellendi.' }); }
    const command = `tail -n ${lines} "${absolutePath}"`;
    sshConnection.exec(command, (err, stream) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        let data = ''; let errorData = '';
        stream.on('data', (c) => data += c.toString()).stderr.on('data', (c) => errorData += c.toString()).on('close', (code) => {
            if (code !== 0 && !data) { return res.status(500).json({ success: false, message: errorData.trim() || `Geçmiş loglar alınamadı (hata kodu: ${code}).` }); }
            res.json({ success: true, history: data.split('\n').filter(Boolean) });
        });
    });
});
// Aktif SSH bağlantısını sonlandırır
app.post('/disconnect', (req, res) => {
    if (sshConnection) {
        try { sshConnection.end(); } catch(e) { console.error("Disconnect sırasında SSH bağlantısı kapatılırken hata:", e); }
        sshConnection = null;
    }
    activeStreams.forEach(s => { if(s.stream) try {s.stream.close();} catch(e){} });
    activeStreams.clear();
    console.log("Bağlantı kesildi (manuel) ve tüm stream'ler durduruldu.");
    res.json({ success: true, message: 'Bağlantı başarıyla sonlandırıldı.' });
});

// --- Alarm ve Bildirim Ayarları Endpoint'leri ---
app.get('/settings/:serverId', async (req, res) => {
    try {
        const serverId = req.params.serverId;
        const docRef = settingsCollection.doc(serverId);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.json({
                success: true,
                settings: { alarms: [], notifications: { browser: { enabled: true }, email: { enabled: false, smtpHost: '', smtpPort: 587, smtpUser: '', smtpPass: '', to: '' }, webhook: { enabled: false, url: '' } } }
            });
        }
        const settings = doc.data();
        // Hassas bilgileri çözerek gönder
        if (settings.notifications.email && settings.notifications.email.smtpPass) {
            try { settings.notifications.email.smtpPass = decrypt(settings.notifications.email.smtpPass); } catch (e) { settings.notifications.email.smtpPass = ''; }
        }
        if (settings.notifications.webhook && settings.notifications.webhook.url) {
            try { settings.notifications.webhook.url = decrypt(settings.notifications.webhook.url); } catch (e) { settings.notifications.webhook.url = ''; }
        }
        res.json({ success: true, settings });
    } catch (error) { console.error("Ayar getirme hatası:", error); res.status(500).json({ success: false, message: 'Ayarlar alınamadı.' }); }
});
app.post('/settings/:serverId', async (req, res) => {
    try {
        const serverId = req.params.serverId;
        const settings = req.body;
        // Hassas bilgileri şifrele
        if (settings.notifications.email && settings.notifications.email.smtpPass) {
            if (settings.notifications.email.smtpPass.includes('******')) {
                 const oldSettingsDoc = await settingsCollection.doc(serverId).get();
                 if (oldSettingsDoc.exists && oldSettingsDoc.data().notifications.email.smtpPass) { settings.notifications.email.smtpPass = oldSettingsDoc.data().notifications.email.smtpPass; }
                 else { settings.notifications.email.smtpPass = null; }
            } else { settings.notifications.email.smtpPass = encrypt(settings.notifications.email.smtpPass); }
        }
        if (settings.notifications.webhook && settings.notifications.webhook.url) {
             if (settings.notifications.webhook.url.includes('******')) {
                 const oldSettingsDoc = await settingsCollection.doc(serverId).get();
                 if (oldSettingsDoc.exists && oldSettingsDoc.data().notifications.webhook.url) { settings.notifications.webhook.url = oldSettingsDoc.data().notifications.webhook.url; }
                 else { settings.notifications.webhook.url = null; }
             } else { settings.notifications.webhook.url = encrypt(settings.notifications.webhook.url); }
        }
        await settingsCollection.doc(serverId).set(settings, { merge: true });
        res.json({ success: true, message: 'Ayarlar başarıyla kaydedildi.' });
    } catch (error) { console.error("Ayar kaydetme hatası:", error); res.status(500).json({ success: false, message: `Ayarlar kaydedilemedi: ${error.message}` }); }
});

// --- WebSocket Bağlantı Yönetimi ---
wss.on('connection', ws => {
    console.log('Yeni bir WebSocket istemcisi bağlandı.');
    let currentStream = null;
    let currentServerId = null;
    let currentFilePath = null;
    let currentSettings = null;
    let alarmCache = []; // { raw: string, regex: RegExp }[]

    // Bildirimleri paralel gönder
    const checkAndNotify = async (logLine) => {
        if (!currentSettings || !currentSettings.alarms || currentSettings.alarms.length === 0) return;
        let matched = false, matchedAlarm = null;
        for (const alarm of alarmCache) {
             if (alarm.regex.test(logLine)) { matched = true; matchedAlarm = alarm.raw; break; }
        }
        if (!matched) return;

        console.log(`ALARM TETİKLENDİ: Sunucu ${currentServerId}, Kural: ${matchedAlarm}`);

        const notificationPromises = [];

        if (currentSettings.notifications.browser.enabled) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'ALARM', alarm: matchedAlarm, line: logLine }));
            }
        }

        const emailSettings = currentSettings.notifications.email;
        if (emailSettings.enabled && emailSettings.smtpHost && emailSettings.to && emailSettings.smtpUser && emailSettings.smtpPass) {
            notificationPromises.push((async () => {
                try {
                    const decryptedPass = decrypt(emailSettings.smtpPass);
                    if (!decryptedPass) throw new Error("SMTP parolası şifreli ama boş veya geçersiz.");
                    let transporter = nodemailer.createTransport({
                        host: emailSettings.smtpHost, port: emailSettings.smtpPort, secure: emailSettings.smtpPort === 465,
                        auth: { user: emailSettings.smtpUser, pass: decryptedPass },
                    });
                    await transporter.sendMail({
                        from: `"Log Yöneticisi" <${emailSettings.smtpUser}>`, to: emailSettings.to, subject: `Log Alarmı: "${matchedAlarm}"`,
                        text: `Merhaba,\n\nİzlediğiniz ${currentFilePath} dosyasında bir alarm tetiklendi.\n\nKural: ${matchedAlarm}\nSatır: ${logLine}`,
                        html: `<p>Merhaba,</p><p>İzlediğiniz <strong>${currentFilePath}</strong> dosyasında bir alarm tetiklendi.</p><p><b>Kural:</b> ${matchedAlarm}</p><p><b>Satır:</b></p><pre>${logLine}</pre>`,
                    });
                    console.log("E-posta bildirimi gönderildi.");
                } catch (emailError) { console.error("E-posta gönderme hatası:", emailError.message); }
            })());
        } else if (emailSettings.enabled) {
            console.warn("E-posta bildirimi etkin ancak SMTP bilgileri (host, to, user, pass) eksik. E-posta gönderilemedi.");
        }

        const webhookSettings = currentSettings.notifications.webhook;
        if (webhookSettings.enabled && webhookSettings.url) {
             notificationPromises.push((async () => {
                 try {
                     const webhookUrl = decrypt(webhookSettings.url);
                     if (!webhookUrl) throw new Error("Webhook URL'si şifreli ama boş veya geçersiz.");
                     const server = await serversCollection.doc(currentServerId).get();
                     const serverName = server.exists ? server.data().name : currentServerId;
                     const payload = { content: `🚨 **Log Alarmı Tetiklendi!** 🚨\n**Sunucu:** ${serverName}\n**Dosya:** \`${currentFilePath}\`\n**Kural:** \`${matchedAlarm}\`\n\`\`\`${logLine}\`\`\`` };
                     await axios.post(webhookUrl, payload);
                     console.log("Webhook bildirimi gönderildi.");
                 } catch (webhookError) { console.error("Webhook gönderme hatası:", webhookError.message); }
             })());
        }
        
        Promise.allSettled(notificationPromises).then(results => {
            results.forEach(result => { if (result.status === 'rejected') console.error("Bir bildirim gönderimi başarısız oldu:", result.reason); });
        });
    };

    ws.on('message', async message => {
        let msg;
        try { msg = JSON.parse(message.toString()); } catch (e) { return; }
        
        if (msg.type === 'START_STREAM') {
            currentServerId = msg.serverId;
            currentFilePath = msg.filePath;
            console.log(`İzleme isteği alındı: Sunucu ${currentServerId}, Dosya ${currentFilePath}`);
            
            try {
                const settingsDoc = await settingsCollection.doc(currentServerId).get();
                if (settingsDoc.exists) {
                    currentSettings = settingsDoc.data();
                    alarmCache = (currentSettings.alarms || []).map(alarm => {
                        let regex;
                        let isRegex = alarm.startsWith('/') && alarm.endsWith('/');
                        try {
                            if (isRegex) {
                                regex = new RegExp(alarm.slice(1, -1), 'i');
                            } else {
                                const escapedAlarm = alarm.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                                regex = new RegExp(escapedAlarm, 'i');
                            }
                            return { raw: alarm, regex: regex };
                        } catch (e) {
                            console.warn(`Geçersiz alarm kuralı: "${alarm}". Yoksayılıyor.`);
                            return null;
                        }
                    }).filter(Boolean);
                    
                } else {
                    currentSettings = { alarms: [], notifications: { browser: { enabled: true }, email: { enabled: false }, webhook: { enabled: false } } };
                    alarmCache = [];
                }
            } catch (e) {
                console.error("Ayarları yüklerken hata:", e);
                ws.send(JSON.stringify({ type: 'LOG', line: `[SYSTEM] Hata: Sunucu ayarları yüklenemedi: ${e.message}` }));
            }

            if (currentStream) { try { currentStream.close(); } catch (e) {} }
            if (!sshConnection) return ws.send(JSON.stringify({ type: 'LOG', line: '[SYSTEM] Hata: Aktif SSH bağlantısı yok.'}));
            
            const fullPath = path.resolve(currentFilePath);
            if (!fullPath.startsWith(path.resolve(BASE_LOG_DIR))) return ws.send(JSON.stringify({ type: 'LOG', line: '[SYSTEM] Hata: Erişim engellendi.'}));

            const command = `tail -f "${fullPath}"`;
            sshConnection.exec(command, (err, stream) => {
                if (err) return ws.send(JSON.stringify({ type: 'LOG', line: `[SYSTEM] Hata: ${err.message}`}));
                console.log(`'${fullPath}' için tail -f başlatıldı.`);
                currentStream = stream;
                
                stream.on('data', data => {
                    const lines = data.toString().split('\n').filter(Boolean);
                    lines.forEach(line => {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'LOG', line: line }));
                        }
                        checkAndNotify(line);
                    });
                })
                .stderr.on('data', data => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'LOG', line: `[SYSTEM] Hata: ${data.toString()}`})); })
                .on('close', () => {
                    console.log(`'${fullPath}' için tail -f sonlandı.`);
                    if (currentStream === stream) currentStream = null;
                    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'LOG', line: '[SYSTEM] Log akışı sonlandı.'}));
                })
                .on('error', (streamErr) => {
                    console.error(`Tail stream hatası (${fullPath}):`, streamErr);
                    if (currentStream === stream) currentStream = null;
                    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'LOG', line: `[SYSTEM] Log akışı hatası: ${streamErr.message}`}));
                });
            });
        }
    });

    ws.on('close', () => {
        console.log('WebSocket istemcisi ayrıldı.');
        if (currentStream) { try { currentStream.close(); } catch (e) {} currentStream = null; }
        activeStreams.delete(ws);
    });
    ws.on('error', (error) => {
        console.error('WebSocket hatası:', error);
        if (currentStream) { try { currentStream.close(); } catch (e) {} currentStream = null; }
        activeStreams.delete(ws);
    });

    activeStreams.set(ws, { stream: null, serverId: null, filePath: null });
});

// Sunucuyu başlat
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde başlatıldı.`);
});

// Uygulama kapanırken SSH bağlantısını düzgünce kapat
process.on('SIGINT', () => {
    console.log("Uygulama kapatılıyor...");
    if (sshConnection) sshConnection.end();
    server.close(() => {
        console.log("HTTP sunucusu kapatıldı.");
        process.exit(0);
    });
});
process.on('uncaughtException', (error) => { console.error('Yakalanmayan Hata:', error); });
process.on('unhandledRejection', (reason, promise) => { console.error('İşlenmeyen Promise Reddi:', reason); });


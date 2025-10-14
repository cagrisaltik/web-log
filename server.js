const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const path = require('path'); // Path modülünü ekledik

const app = express();
app.use(express.json());

const PORT = 3000;

let sshConnection = null;
let activeLogStream = null;

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// YENİ: Güvenlik için izin verilen ana dizin
const BASE_LOG_DIR = '/var/log';

app.get('/', (req, res) => {
    res.send('Backend sunucusu başarıyla çalışıyor!');
});

app.post('/connect', (req, res) => {
    if (sshConnection) {
        return res.json({ success: true, message: 'Zaten aktif bir bağlantı var.' });
    }

    const { ip, user, pass } = req.body;
    const conn = new Client();

    conn.on('ready', () => {
        console.log('SSH Bağlantısı Başarılı!');
        sshConnection = conn;
        res.json({ success: true, message: 'Sunucuya başarıyla bağlanıldı!' });
    }).on('error', (err) => {
        console.error('SSH Bağlantı Hatası:', err.message);
        res.status(500).json({ success: false, message: `Bağlantı hatası: ${err.message}` });
    }).connect({
        host: ip,
        port: 22,
        username: user,
        password: pass,
        readyTimeout: 20000
    });
});

// GÜNCELLENDİ: Artık bir yol alabilen /browse endpoint'i
app.post('/browse', (req, res) => {
    if (!sshConnection) {
        return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
    }

    const requestedSubPath = req.body.path || '/';

    // GÜVENLİK KONTROLÜ: Kullanıcının /var/log dışına çıkmasını engelle
    const fullPath = path.join(BASE_LOG_DIR, requestedSubPath);
    const absolutePath = path.resolve(fullPath);

    if (!absolutePath.startsWith(path.resolve(BASE_LOG_DIR))) {
        return res.status(403).json({ success: false, message: 'Erişim engellendi.' });
    }

    const command = `ls -F ${absolutePath}`;
    console.log(`Komut çalıştırılıyor: ${command}`);

    sshConnection.exec(command, (err, stream) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }
        let data = '';
        stream.on('data', (chunk) => {
            data += chunk.toString();
        }).on('close', () => {
            const items = data.split('\n').filter(Boolean).map(item => {
                const isDirectory = item.endsWith('/');
                return {
                    name: item,
                    type: isDirectory ? 'directory' : 'file'
                };
            });
            res.json({ success: true, items: items });
        }).stderr.on('data', (data) => {
            console.error('STDERR:', data.toString());
            res.status(500).json({ success: false, message: data.toString().trim() });
        });
    });
});


app.post('/disconnect', (req, res) => {
    if (sshConnection) {
        sshConnection.end();
        sshConnection = null;
        console.log('SSH bağlantısı sonlandırıldı.');
    }
    res.json({ success: true, message: 'Bağlantı başarıyla sonlandırıldı.' });
});

wss.on('connection', ws => {
    console.log('Yeni bir WebSocket istemcisi bağlandı.');
    
    ws.on('message', message => {
        const filePath = message.toString();
        console.log(`İzleme isteği alındı: ${filePath}`);

        if (activeLogStream) {
            activeLogStream.close();
        }

        if (!sshConnection) {
            ws.send('[SYSTEM] Hata: Aktif SSH bağlantısı yok.');
            return;
        }
        
        // GÜVENLİK KONTROLÜ: İzlenen dosyanın da /var/log içinde olduğundan emin ol
        const fullPath = path.resolve(filePath);
        if (!fullPath.startsWith(path.resolve(BASE_LOG_DIR))) {
             ws.send('[SYSTEM] Hata: Erişim engellendi.');
             return;
        }

        const command = `tail -f ${filePath}`;
        sshConnection.exec(command, (err, stream) => {
            if (err) {
                ws.send(`[SYSTEM] Hata: ${err.message}`);
                return;
            }
            activeLogStream = stream;
            stream.on('data', data => {
                ws.send(data.toString());
            }).stderr.on('data', data => {
                ws.send(`[SYSTEM] Hata: ${data.toString()}`);
            });
        });
    });

    ws.on('close', () => {
        console.log('WebSocket istemcisi ayrıldı.');
        if (activeLogStream) {
            activeLogStream.close();
            activeLogStream = null;
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde başlatıldı.`);
});



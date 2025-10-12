const express = require('express');
const { Client } = require('ssh2');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors'); // <-- YENİ: cors kütüphanesini dahil et

const app = express();
const PORT = 3000;

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
// <-- YENİ: Gelen tüm isteklere izin vermek için cors'u etkinleştir.

let sshConnection = null;

// --- WEBSOCKET BAĞLANTI MANTIĞI ---
wss.on('connection', (ws) => {
  console.log('Yeni bir WebSocket istemcisi bağlandı.');
  let tailStream = null;

  ws.on('message', (message) => {
    const logFile = message.toString();
    console.log(`İzleme isteği alındı: ${logFile}`);
    if (!sshConnection) {
      console.error('WebSocket: SSH bağlantısı aktif değil.');
      ws.send('HATA: Sunucuya SSH bağlantısı yok.');
      return;
    }
    if (tailStream) tailStream.close();
    
    const command = `tail -f ${logFile}`;
    sshConnection.exec(command, (err, stream) => {
      if (err) {
        console.error('Tail komutu çalıştırma hatası:', err.message);
        ws.send(`HATA: ${logFile} izlenemedi.`);
        return;
      }
      tailStream = stream;
      stream.on('data', (data) => {
        ws.send(data.toString());
      });
      stream.on('close', () => {
        console.log(`Tail stream kapatıldı: ${logFile}`);
      });
    });
  });

  ws.on('close', () => {
    console.log('WebSocket istemcisi bağlantıyı kesti.');
    if (tailStream) {
      tailStream.close();
    }
  });
});

// --- EXPRESS API ENDPOINTLERİ (DEĞİŞİKLİK YOK) ---
app.get('/', (req, res) => {
  res.send('Backend sunucusu çalışıyor! WebSocket bağlantılarına hazır.');
});

app.post('/connect', (req, res) => {
  if (sshConnection) sshConnection.end();
  const { ip, user, pass } = req.body;
  if (!ip || !user || !pass) return res.status(400).json({ success: false, message: 'Eksik bilgi.' });
  
  const conn = new Client();
  conn.on('ready', () => {
    console.log('SSH Bağlantısı Başarılı!');
    sshConnection = conn;
    res.status(200).json({ success: true, message: 'Sunucuya başarıyla bağlanıldı!' });
  }).on('error', (err) => {
    console.error('SSH Bağlantı Hatası:', err.message);
    sshConnection = null;
    res.status(500).json({ success: false, message: `Bağlantı hatası: ${err.message}` });
  });
  conn.connect({ host: ip, port: 22, username: user, password: pass });
});

app.get('/list-logs', (req, res) => {
  if (!sshConnection) return res.status(400).json({ success: false, message: 'Aktif bir sunucu bağlantısı yok.' });
  sshConnection.exec('ls -1 /var/log/*.log', (err, stream) => {
    if (err) return res.status(500).json({ success: false, message: 'Komut çalıştırılamadı.' });
    let fileList = '';
    stream.on('data', (data) => { fileList += data.toString(); });
    stream.on('close', () => {
      const files = fileList.split('\n').filter(Boolean);
      res.status(200).json({ success: true, files: files });
    });
  });
});

app.post('/disconnect', (req, res) => {
  if (sshConnection) {
    sshConnection.end();
    sshConnection = null;
    console.log('SSH bağlantısı sonlandırıldı.');
    res.status(200).json({ success: true, message: 'Bağlantı sonlandırıldı.' });
  } else {
    res.status(400).json({ success: false, message: 'Aktif bağlantı yok.' });
  }
});

// --- SUNUCUYU BAŞLATMA ---
server.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde başlatıldı.`);
});



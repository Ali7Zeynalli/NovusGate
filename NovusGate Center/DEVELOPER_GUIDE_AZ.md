# NovusGate Center - Developer Təlimatı

## İcmal

**NovusGate Center**, uzaq Linux serverlərdə NovusGate VPN-in yerləşdirilməsi, yenilənməsi və idarə edilməsi üçün veb əsaslı idarəetmə alətidir. Yerli olaraq (Docker vasitəsilə) işləyir və SSH üzərindən hədəf serverlərə qoşulur.

## Arxitektura

### Texnologiya Yığını
| Komponent | Texnologiya |
|-----------|-------------|
| Backend | Node.js 20, Express.js |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| SSH | `ssh2` kitabxanası |
| Fayl Transferi | SFTP (ssh2 vasitəsilə) |
| Yerləşdirmə | Docker & Docker Compose |

### Fayl Strukturu
```
NovusGate Center/
├── server.js              # Əsas backend - API endpointləri və install skriptləri
├── log_service.js         # Docker log streaming xidməti
├── public/
│   └── index.html         # Tək səhifəli frontend tətbiqi
├── data/
│   └── servers.json       # Saxlanılan server məlumatları
├── Dockerfile             # Konteyner tərifi
├── docker-compose.yml     # Orkestrasiya konfiqurasiyası
├── package.json           # Node.js asılılıqları
└── .env                   # Mühit dəyişənləri (PORT)
```

## Əsas Komponentlər

### 1. Backend API (`server.js`)

#### Server İdarəetmə Endpointləri
| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `GET` | `/api/servers` | Bütün serverləri siyahıla |
| `POST` | `/api/servers` | Yeni server əlavə et |
| `DELETE` | `/api/servers/:id` | Serveri sil |
| `GET` | `/api/servers/:id/status` | Server sağlamlığını və quraşdırma statusunu yoxla |

#### Quraşdırma Endpointləri
| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `POST` | `/api/servers/:id/install` | NovusGate quraşdır/yenilə/yenidən quraşdır |
| `POST` | `/api/servers/:id/uninstall` | Tam silmə |
| `POST` | `/api/servers/:id/command` | Xüsusi SSH əmri icra et |

#### Docker İdarəetmə Endpointləri
| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `GET` | `/api/servers/:id/docker` | Konteynerləri siyahıla |
| `POST` | `/api/servers/:id/docker/:action` | Konteyner idarəsi (start/stop/restart/logs) |
| `GET` | `/api/servers/:id/docker/logs/stream` | Canlı log yayımı (SSE) |
| `GET` | `/api/servers/:id/images` | Docker şəkillərini siyahıla |
| `DELETE` | `/api/servers/:id/images/:name` | Şəkil sil |
| `GET` | `/api/servers/:id/volumes` | Docker volume-ları siyahıla |
| `DELETE` | `/api/servers/:id/volumes/:name` | Volume sil |
| `POST` | `/api/servers/:id/prune` | İstifadə olunmayan resursları təmizlə |

### 2. Daxil Edilmiş Install Skriptləri

Bütün quraşdırma məntiqi `server.js`-də template literal olaraq saxlanılır:

| Skript | Məqsəd |
|--------|--------|
| `GENERATE_INSTALL_SCRIPT(config)` | Konfiqurasiya ilə təmiz quraşdırma |
| `GENERATE_REINSTALL_SCRIPT(config)` | Məlumatları qoruyaraq yenidən quraşdırma |
| `UPDATE_SCRIPT` | Ağıllı yeniləmə - yalnız dəyişən komponentlər |
| `UNINSTALL_SCRIPT` | Tam silmə |
| `DATABASE_MIGRATE_SCRIPT` | Yalnız verilənlər bazası miqrasiyası |

### 3. Quraşdırma Axını

```
┌─────────────────┐
│  İstifadəçi     │
│  "Install" basır│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Arxiv Yarat     │  tar -czf NovusGate.tar.gz server/ web/
│ (yerli fayllar) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SSH Qoşulma     │  ssh2 kitabxanası
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Arxiv Yüklə     │  SFTP ilə /tmp/NovusGate.tar.gz
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Skript İcra Et  │  INSTALL_SCRIPT uzaq serverdə işləyir
│ (streaming)     │  stdout/stderr → SSE → Frontend
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Çıxışı Oxu      │  Çıxar: API_KEY, ADMIN_PASS, VPN Config
└─────────────────┘
```

### 4. Ağıllı Yeniləmə Axını (v2.0)

Yeniləmə skripti nəyin dəyişdiyini aşkarlayır və yalnız təsirlənən komponentləri yenidən qurur:

```bash
# Aşkarlama Məntiqi
SERVER_CHANGED=false   # server/ qovluğu
WEB_CHANGED=false      # web/ qovluğu
DOCKER_CHANGED=false   # docker-compose.yml və ya Dockerfile-lar

# Seçici Yenidənqurma
if SERVER_CHANGED && WEB_CHANGED:
    control-plane, web yenidən qur
elif SERVER_CHANGED:
    yalnız control-plane yenidən qur
elif WEB_CHANGED:
    yalnız web yenidən qur
elif DOCKER_CHANGED:
    tam yenidənqurma
else:
    "Dəyişiklik aşkarlanmadı"
```

### 5. Frontend (`public/index.html`)

Tək fayllı SPA:
- **Server Siyahısı Sidebar** - Çoxlu serverləri idarə et
- **Dashboard Görünüşü** - Status, resurslar, konteynerlər
- **Real-vaxt Logları** - Backend-dən SSE streaming
- **Məlumat Göstərimi** - Install çıxışından avtomatik oxunur
- **VPN Config Yükləmə** - Install çıxışından çıxarılır

## Əsas Xüsusiyyətlər

### SSH Bağlantısı
```javascript
function createSSHConnection(server) {
  const config = {
    host: server.host,
    port: server.port || 22,
    username: server.username,
    readyTimeout: 30000
  };
  
  if (server.privateKey) {
    config.privateKey = server.privateKey;
  } else if (server.password) {
    config.password = server.password;
  }
  
  conn.connect(config);
}
```

### Arxiv Yaratma
```javascript
const excludes = [
  '--exclude=node_modules',
  '--exclude=.git',
  '--exclude=*.exe',
  '--exclude=*.tar.gz',
  '--exclude=*.log',
  '--exclude=.env',
  '--exclude=.idea',
  '--exclude=.vscode'
];

const tarCommand = `tar -czf "${archivePath}" -C "${PROJECT_ROOT}" ${excludes} server web`;
```

### Real-vaxt Streaming
```javascript
// Backend: SSE (Server-Sent Events)
res.setHeader('Content-Type', 'text/event-stream');
res.write(`data: ${JSON.stringify({ text: output })}\n\n`);

// Frontend: EventSource
const source = new EventSource(`/api/servers/${id}/docker/logs/stream?container=${name}`);
source.onmessage = (e) => {
  const data = JSON.parse(e.data);
  outputLog.textContent += data.text;
};
```

## Konfiqurasiya

### Mühit Dəyişənləri
| Dəyişən | Default | Təsvir |
|---------|---------|--------|
| `PORT` | `3017` | NovusGate Center veb server portu |

### Install Konfiqurasiyası (skriptlərə ötürülür)
| Parametr | Default | Təsvir |
|----------|---------|--------|
| `adminUsername` | `admin` | Dashboard admin istifadəçi adı |
| `adminPassword` | avtomatik | Dashboard admin parolu |
| `vpnIp` | `10.99.0.1` | Admin VPN gateway IP |
| `dbName` | `NovusGate` | PostgreSQL verilənlər bazası adı |
| `dbUser` | `NovusGate` | PostgreSQL istifadəçi adı |
| `dbPassword` | avtomatik | PostgreSQL parolu |

## İnkişaf

### Yerli İnkişaf
```bash
cd "NovusGate Center"
npm install
node server.js
# Giriş: http://localhost:3017
```

### Docker İnkişafı
```bash
cd "NovusGate Center"
docker-compose up -d --build
# Giriş: http://localhost:3017
```

### SSH Bağlantısını Test Etmək
```javascript
// /api/servers/:id/command endpoint istifadə edin
POST /api/servers/abc123/command
{
  "command": "whoami && hostname"
}
```

## Təhlükəsizlik Mülahizələri

1. **Məlumat Saxlama** - Server parolları `data/servers.json`-da saxlanılır (MVP üçün açıq mətn)
2. **SSH Açarları** - `privateKey` sahəsi vasitəsilə dəstəklənir
3. **Yaradılan Sirlər** - API açarları və parollar `openssl rand -hex 16` istifadə edir
4. **VPN Təhlükəsizliyi** - Admin paneli yalnız WireGuard VPN (wg0) vasitəsilə əlçatandır

## Problemlərin Həlli

### Ümumi Problemlər

| Problem | Səbəb | Həll |
|---------|-------|------|
| "Cannot execute: required file not found" | Windows CRLF sətir sonları | Skript `sed -i 's/\r$//'` düzəlişi daxildir |
| "ADMIN_PASSWORD is required" | .env faylı yoxdur | docker-compose-dan əvvəl .env mövcud olmalıdır |
| Firewall-dan sonra konteynerlər dayanır | Firewall skriptində Docker restart | Skript indi sonra konteynerləri yenidən başladır |
| Arxiv yaratma uğursuz | tar əmri yoxdur | Windows-da tar quraşdırın və ya WSL istifadə edin |

### Debug Endpointləri
- `GET /api/health` - NovusGate Center sağlamlığını yoxla
- `POST /api/servers/:id/command` - İstənilən əmri icra et

## Töhfə Vermək

1. **Kod Stili** - ES6+, async/await istifadə edin
2. **Skriptlər** - Bütün .sh fayllarının LF sətir sonları olduğundan əmin olun
3. **Test** - Ubuntu 22.04 LTS-də test edin
4. **Sənədləşdirmə** - Yeni xüsusiyyətlər üçün təlimatları yeniləyin

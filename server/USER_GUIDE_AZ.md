# NovusGate Server - İstifadəçi Təlimatı

## Giriş

**NovusGate Server**, VPN şəbəkənizin onurğa sütunudur. Arxa planda səssizcə işləyərək cihazlarınız arasındakı təhlükəsiz şifrələnmiş tunelləri idarə edir.

## Quraşdırma

*Qeyd: Avtomatik yerləşdirmə üçün **NovusGate Center** istifadə etməyiniz tövsiyə olunur.*

### Docker Yerləşdirməsi (Manual)

Əgər manual olaraq Docker ilə işlətmək istəyirsinizsə:

1. **`docker-compose.yml` yaradın:**
```yaml
version: "3.8"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: NovusGate
      POSTGRES_USER: NovusGate
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./data/postgres:/var/lib/postgresql/data

  control-plane:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.control-plane
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - /etc/wireguard:/etc/wireguard:rw
    env_file: .env
    depends_on:
      - postgres
```

2. **`.env` konfiqurasiyası yaradın:**
```bash
# Verilənlər Bazası
DB_NAME=NovusGate
DB_USER=NovusGate
DB_PASSWORD=guclu_parol_123

# Təhlükəsizlik
JWT_SECRET=cox_guclu_tesadufi_kod
API_KEY=daxili_elaqe_ucun_kod
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin_parolu

# Şəbəkə
WG_SERVER_ENDPOINT=SIZIN_PUBLIC_IP
ADMIN_CIDR=10.99.0.0/24
```

3. **İşə salın:**
```bash
docker-compose up -d
```

## Konfiqurasiya

### Mühit Dəyişənləri

| Dəyişən | Təsvir | Default |
|---------|--------|---------|
| `DATABASE_URL` | PostgreSQL bağlantı string-i | Məcburi |
| `JWT_SECRET` | API tokenlərini imzalamaq üçün gizli açar | Məcburi |
| `NovusGate_API_KEY` | Xidmətlərarası əlaqə üçün açar | Məcburi |
| `ADMIN_USERNAME` | İlk admin istifadəçi adı | `admin` |
| `ADMIN_PASSWORD` | İlk admin parolu | Məcburi |
| `WG_SERVER_ENDPOINT` | Müştərilərin qoşulacağı İctimai IP | Məcburi |
| `ADMIN_CIDR` | Admin şəbəkə CIDR aralığı | `10.99.0.0/24` |
| `NovusGate_LISTEN` | API dinləmə portu | `:8080` |
| `NovusGate_GRPC_LISTEN` | gRPC dinləmə portu | `:8443` |

### Məlumatların Saxlanması

- **Verilənlər Bazası:** PostgreSQL-də saxlanılır (`data/postgres/`)
- **WireGuard Konfiqurasiyaları:** `/etc/wireguard/` qovluğunda
- **Backup:** `data/` qovluğunu və PostgreSQL-i mütəmadi olaraq yedəkləyin

## Şəbəkə Strukturu

NovusGate çoxlu VPN şəbəkələrini dəstəkləyir:

```
┌─────────────────────────────────────────────────────────────┐
│                    NovusGate Server                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Admin Network   │  │ Office Network  │                  │
│  │ wg0 (51820)     │  │ wg1 (51821)     │                  │
│  │ 10.99.0.0/24    │  │ 10.10.0.0/24    │                  │
│  │                 │  │                 │                  │
│  │ ● Admin Panel   │  │ ● İşçi 1        │                  │
│  │ ● Monitoring    │  │ ● İşçi 2        │                  │
│  └─────────────────┘  │ ● Server        │                  │
│                       └─────────────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Admin Network (wg0)
- **Məqsəd:** Admin panelə təhlükəsiz giriş
- **CIDR:** `10.99.0.0/24` (default)
- **Port:** 51820
- **Xüsusiyyət:** Silinə bilməz

### Əlavə Şəbəkələr (wg1, wg2, ...)
- Dashboard-dan yaradılır
- Hər biri öz CIDR aralığına malikdir
- Müstəqil peer-lər

## API Endpoint-ləri

Server REST API təmin edir:

### Autentifikasiya
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/auth/login` | POST | Giriş (token al) |
| `/api/v1/auth/password` | PUT | Parol dəyiş |

### Şəbəkələr
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/networks` | GET | Şəbəkələri siyahıla |
| `/api/v1/networks` | POST | Yeni şəbəkə yarat |
| `/api/v1/networks/{id}` | GET | Şəbəkə detalları |
| `/api/v1/networks/{id}` | DELETE | Şəbəkəni sil |

### Node-lar (Peer-lər)
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/networks/{id}/nodes` | GET | Node-ları siyahıla |
| `/api/v1/networks/{id}/servers` | POST | Yeni peer yarat |
| `/api/v1/nodes/{id}` | GET | Node detalları |
| `/api/v1/nodes/{id}` | PUT | Node yenilə |
| `/api/v1/nodes/{id}` | DELETE | Node sil |
| `/api/v1/nodes/{id}/config` | GET | WireGuard konfiqurasiyası |
| `/api/v1/nodes/{id}/qrcode` | GET | QR kod şəkli |

### İstifadəçilər
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/users` | GET | İstifadəçiləri siyahıla |
| `/api/v1/users` | POST | Yeni istifadəçi yarat |
| `/api/v1/users/{id}` | DELETE | İstifadəçi sil |

### Host Firewall
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/firewall/rules` | GET | Bütün firewall qaydalarını və statusunu al |
| `/api/v1/firewall/open-port` | POST | Gələn trafik üçün port aç |
| `/api/v1/firewall/close-port` | POST | Açıq portu bağla |
| `/api/v1/firewall/block-ip` | POST | IP ünvanı və ya CIDR-i blokla |
| `/api/v1/firewall/allow-ip` | POST | IP ünvanı və ya CIDR-ə icazə ver |
| `/api/v1/firewall/rules` | DELETE | Firewall qaydasını sil |
| `/api/v1/firewall/reset` | POST | Firewall-u defolt konfiqurasiyaya sıfırla |
| `/api/v1/firewall/export` | GET | Firewall qaydalarını mətn olaraq export et |

### VPN Firewall (Şəbəkələrarası Qaydalar)
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/api/v1/vpn-firewall/rules` | GET | Bütün VPN firewall qaydalarını siyahıla |
| `/api/v1/vpn-firewall/rules` | POST | Yeni VPN qaydası yarat |
| `/api/v1/vpn-firewall/rules/{id}` | PUT | VPN qaydasını yenilə |
| `/api/v1/vpn-firewall/rules/{id}` | DELETE | VPN qaydasını sil |
| `/api/v1/vpn-firewall/apply` | POST | VPN qaydalarını iptables-ə tətbiq et |

### Sağlamlıq
| Endpoint | Metod | Təsvir |
|----------|-------|--------|
| `/health` | GET | Server statusu |

## Node Statusları

| Status | Təsvir | Rəng |
|--------|--------|------|
| `pending` | Konfiqurasiya gözləyir | Sarı |
| `online` | Aktiv bağlantı var | Yaşıl |
| `offline` | Bağlantı yoxdur | Boz |
| `expired` | Vaxtı bitib | Qırmızı |

### Online Aşkarlaması
Server iki üsulla online statusu müəyyən edir:

1. **Trafik Aktivliyi** (~30-45 saniyə)
   - PersistentKeepalive=25 ilə client-lər hər 25 saniyədə data göndərir
   - Son 45 saniyədə trafik varsa = online

2. **Handshake Vaxtı** (~2.5 dəqiqə)
   - WireGuard handshake timestamp-i
   - Son 150 saniyədə handshake varsa = online

## Problemlərin Həlli

### "Müştərilər qoşula bilmir"
- Firewall-da **51820 UDP** portunun açıq olduğunu yoxlayın
- `.env` faylında `WG_SERVER_ENDPOINT` dəyərinin real İctimai IP ilə eyni olduğunu yoxlayın
- `wg show` əmri ilə interfeys statusunu yoxlayın

### "Server restart loop-da"
- Logları yoxlayın: `docker logs NovusGate-control-plane`
- Ən çox rast gəlinən səbəblər:
  - PostgreSQL bağlantı xətası
  - `/etc/wireguard` qovluğuna giriş yoxdur
  - `ADMIN_PASSWORD` təyin edilməyib

### "API 500 Error"
- `JWT_SECRET` dəyərinin təyin olunduğunu yoxlayın
- Verilənlər bazası bağlantısını yoxlayın
- Server loglarında xəta mesajını axtarın

### "Peer-lər görünmür"
- WireGuard interfeysin UP olduğunu yoxlayın: `ip link show wg0`
- Peer-in WireGuard-a əlavə olunduğunu yoxlayın: `wg show wg0`
- Verilənlər bazasında node-un mövcud olduğunu yoxlayın

### "Network yaradıla bilmir"
- CIDR aralığının mövcud şəbəkələrlə overlap etmədiyini yoxlayın
- WireGuard tools-un quraşdırıldığını yoxlayın: `which wg`

## Logları Görmək

```bash
# Bütün konteynerlərin logları
docker-compose logs -f

# Yalnız control-plane
docker logs -f NovusGate-control-plane

# WireGuard statusu
wg show

# Şəbəkə interfeyslərini yoxla
ip addr show
```

## Təhlükəsizlik Tövsiyələri

1. **Güclü parollar istifadə edin** - `JWT_SECRET`, `API_KEY`, `ADMIN_PASSWORD` üçün
2. **Firewall konfiqurasiya edin** - Yalnız lazımi portları açın
3. **VPN arxasında saxlayın** - Admin panel yalnız wg0 üzərindən əlçatan olmalıdır
4. **Müntəzəm yedəkləyin** - PostgreSQL və `/etc/wireguard` qovluğunu
5. **Logları izləyin** - Şübhəli fəaliyyət üçün

## Portlar

| Port | Protokol | Təsvir |
|------|----------|--------|
| 8080 | TCP | REST API |
| 8443 | TCP | gRPC (gələcək istifadə üçün) |
| 51820+ | UDP | WireGuard (hər şəbəkə üçün bir port) |
| 5432 | TCP | PostgreSQL (yalnız localhost) |
| 3007 | TCP | Web Dashboard |

## Dəstək

- **Developer:** [Ali Zeynalli](https://github.com/Ali7Zeynalli)
- **Problemlər:** GitHub repozitoriyasında issue açın
- **Sənədləşdirmə:** Texniki detallar üçün DEVELOPER_GUIDE_AZ.md-ə baxın

# NovusGate Server - Developer Təlimatı

## İcmal

**NovusGate Server**, WireGuard mesh şəbəkə overlay-ini idarə edən əsas komponentdir. Peer koordinasiyası, konfiqurasiya paylanması, açar idarəetməsi və dashboard üçün API girişini təmin edir. **Go** dilində yazılıb və yüksək performanslı, cloud-native dizayn edilib.

## Arxitektura

### Texnologiya Yığını
| Komponent | Texnologiya |
|-----------|-------------|
| Dil | Go 1.23+ |
| Verilənlər Bazası | PostgreSQL 16 |
| VPN Protokolu | WireGuard (`wg-quick` və kernel modulları) |
| API | REST/JSON HTTP üzərindən |
| Autentifikasiya | JWT (JSON Web Tokens) + API Key |
| Router | Gorilla Mux |

### Qovluq Strukturu
```
server/
├── cmd/
│   └── control-plane/
│       └── main.go           # Əsas giriş nöqtəsi (CLI əmrləri)
├── internal/
│   ├── controlplane/
│   │   ├── api/
│   │   │   └── rest/
│   │   │       └── handlers.go   # REST API handler-ləri
│   │   └── store/
│   │       └── store.go          # PostgreSQL verilənlər bazası əməliyyatları
│   ├── wireguard/
│   │   ├── manager.go            # WireGuard interfeys idarəetməsi
│   │   ├── keys.go               # Açar yaratma
│   │   ├── config_generator.go   # Konfiqurasiya yaratma
│   │   └── install_script.go     # Client quraşdırma skripti
│   └── shared/
│       └── models/
│           └── models.go         # Data modelləri
├── deployments/
│   └── docker/
│       ├── docker-compose.yml    # Orkestrasiya
│       ├── Dockerfile.control-plane
│       └── setup-firewall.sh     # Firewall konfiqurasiyası
├── go.mod                        # Go modulları
└── go.sum                        # Asılılıq hash-ləri
```

## Əsas Modullar

### 1. Control Plane (`internal/controlplane`)

Bu modul sistemin "beyni" rolunu oynayır.

#### API Layer (`api/rest/handlers.go`)
REST API endpoint-lərini təmin edir:

| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `POST` | `/api/v1/auth/login` | İstifadəçi girişi |
| `PUT` | `/api/v1/auth/password` | Parol dəyişmə |
| `GET` | `/api/v1/networks` | Şəbəkələri siyahıla |
| `POST` | `/api/v1/networks` | Yeni şəbəkə yarat |
| `DELETE` | `/api/v1/networks/{id}` | Şəbəkəni sil |
| `GET` | `/api/v1/networks/{networkId}/nodes` | Node-ları siyahıla |
| `POST` | `/api/v1/networks/{networkId}/servers` | Yeni server/peer yarat |
| `GET` | `/api/v1/nodes/{id}` | Node məlumatı |
| `PUT` | `/api/v1/nodes/{id}` | Node yenilə |
| `DELETE` | `/api/v1/nodes/{id}` | Node sil |
| `GET` | `/api/v1/nodes/{id}/config` | WireGuard konfiqurasiyası |
| `GET` | `/api/v1/nodes/{id}/qrcode` | QR kod şəkli |
| `GET` | `/api/v1/users` | İstifadəçiləri siyahıla |
| `POST` | `/api/v1/users` | Yeni istifadəçi yarat |
| `DELETE` | `/api/v1/users/{id}` | İstifadəçi sil |
| `GET` | `/health` | Sağlamlıq yoxlaması |

**Host Firewall Endpoint-ləri (`firewall_handlers.go`):**

| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `GET` | `/api/v1/firewall/rules` | Bütün firewall qaydalarını al |
| `POST` | `/api/v1/firewall/open-port` | Port aç |
| `POST` | `/api/v1/firewall/close-port` | Port bağla |
| `POST` | `/api/v1/firewall/block-ip` | IP/CIDR blokla |
| `POST` | `/api/v1/firewall/allow-ip` | IP/CIDR-ə icazə ver |
| `DELETE` | `/api/v1/firewall/rules` | Qayda sil |
| `POST` | `/api/v1/firewall/reset` | Defolta sıfırla |
| `GET` | `/api/v1/firewall/export` | Qaydaları export et |

**VPN Firewall Endpoint-ləri (`vpn_firewall_handlers.go`):**

| Metod | Endpoint | Təsvir |
|-------|----------|--------|
| `GET` | `/api/v1/vpn-firewall/rules` | VPN qaydalarını siyahıla |
| `POST` | `/api/v1/vpn-firewall/rules` | VPN qaydası yarat |
| `PUT` | `/api/v1/vpn-firewall/rules/{id}` | VPN qaydasını yenilə |
| `DELETE` | `/api/v1/vpn-firewall/rules/{id}` | VPN qaydasını sil |
| `POST` | `/api/v1/vpn-firewall/apply` | Qaydaları iptables-ə tətbiq et |

#### Store Layer (`store/store.go`)
PostgreSQL verilənlər bazası əməliyyatları:

```go
// Əsas funksiyalar
func (s *Store) CreateNetwork(ctx, network) error
func (s *Store) GetNetwork(ctx, id) (*Network, error)
func (s *Store) ListNetworks(ctx) ([]*Network, error)
func (s *Store) DeleteNetwork(ctx, id) error

func (s *Store) CreateNode(ctx, node) error
func (s *Store) GetNode(ctx, id) (*Node, error)
func (s *Store) ListNodes(ctx, networkID) ([]*Node, error)
func (s *Store) UpdateNode(ctx, node) error
func (s *Store) DeleteNode(ctx, id) error
func (s *Store) AllocateIP(ctx, networkID) (net.IP, error)

func (s *Store) CreateUser(ctx, user) error
func (s *Store) GetUserByUsername(ctx, username) (*User, error)
func (s *Store) UpdateUserPassword(ctx, username, hash) error
```

### 2. WireGuard Manager (`internal/wireguard`)

WireGuard interfeyslərini idarə edir.

#### manager.go
```go
type Manager struct {
    InterfaceName string  // wg0, wg1, ...
    ConfigPath    string  // /etc/wireguard/wg0.conf
}

// Əsas metodlar
func (m *Manager) Init() error                    // wg əmrinin mövcudluğunu yoxla
func (m *Manager) Up() error                      // wg-quick up
func (m *Manager) Down() error                    // wg-quick down
func (m *Manager) AddPeer(pubKey, allowedIPs)     // Peer əlavə et
func (m *Manager) RemovePeer(pubKey)              // Peer sil
func (m *Manager) GetPeers() map[string]PeerStatus // Peer statusları
func (m *Manager) GetPublicKey() (string, error)  // Server public key
```

#### PeerStatus strukturu
```go
type PeerStatus struct {
    PublicKey           string
    Endpoint            string
    AllowedIPs          string
    LatestHandshakeTime int64   // Unix timestamp
    TransferRx          int64   // Bytes received
    TransferTx          int64   // Bytes sent
}
```

### 3. Data Modelləri (`internal/shared/models`)

#### Network
```go
type Network struct {
    ID               string    // UUID
    Name             string    // "Admin Management", "Office VPN"
    CIDR             string    // "10.10.0.0/24"
    ServerPrivateKey string    // WireGuard private key (gizli)
    ServerPublicKey  string    // WireGuard public key
    ServerEndpoint   string    // "64.225.108.60:51820"
    ListenPort       int       // 51820, 51821, ...
    InterfaceName    string    // "wg0", "wg1", ...
    CreatedAt        time.Time
    UpdatedAt        time.Time
}
```

#### Node
```go
type Node struct {
    ID         string            // UUID
    NetworkID  string            // Hansı şəbəkəyə aid
    Name       string            // "Əlinin Laptopı"
    VirtualIP  net.IP            // 10.10.0.5
    PublicKey  string            // Client public key
    Labels     map[string]string // Metadata
    Status     NodeStatus        // pending/online/offline/expired
    LastSeen   time.Time
    PublicIP   string            // Real IP (endpoint-dən)
    TransferRx int64             // Download bytes
    TransferTx int64             // Upload bytes
    ExpiresAt  *time.Time        // Bitmə vaxtı (optional)
    NodeInfo   *NodeInfo         // OS, arch, hostname
    CreatedAt  time.Time
}
```

#### NodeStatus
```go
const (
    NodeStatusPending NodeStatus = "pending"   // Konfiqurasiya gözləyir
    NodeStatusOnline  NodeStatus = "online"    // Aktiv bağlantı
    NodeStatusOffline NodeStatus = "offline"   // Bağlantı yoxdur
    NodeStatusExpired NodeStatus = "expired"   // Vaxtı bitib
)
```

## CLI Əmrləri

Server `cobra` kitabxanası ilə CLI təmin edir:

```bash
# Serveri işə sal
NovusGate-server serve --listen :8080 --grpc-listen :8443

# Verilənlər bazası miqrasiyası
NovusGate-server migrate --database "postgres://..."

# Şəbəkə inisializasiyası
NovusGate-server init --name "Admin Network" --cidr "10.99.0.0/24"

# Versiya
NovusGate-server version
```

## Middleware-lər

### 1. AuthMiddleware
JWT token yoxlaması:
```go
// Authorization: Bearer <token>
// /health və /login endpoint-ləri istisnadır
```

### 2. APIKeyMiddleware
API açar yoxlaması:
```go
// X-API-Key: <key>
// Dev mode-da (boş key) atlanır
```

### 3. LoggingMiddleware
Request logging (hazırda placeholder).

## Mühit Dəyişənləri

| Dəyişən | Təsvir | Default |
|---------|--------|---------|
| `DATABASE_URL` | PostgreSQL bağlantı string-i | Məcburi |
| `NovusGate_LISTEN` | HTTP API portu | `:8080` |
| `NovusGate_GRPC_LISTEN` | gRPC portu | `:8443` |
| `JWT_SECRET` | Token imzalama açarı | Məcburi |
| `NovusGate_API_KEY` | API açarı | Məcburi |
| `ADMIN_USERNAME` | İlk admin istifadəçi adı | `admin` |
| `ADMIN_PASSWORD` | İlk admin parolu | Məcburi |
| `WG_SERVER_ENDPOINT` | Server public IP | Məcburi |
| `ADMIN_CIDR` | Admin şəbəkə CIDR | `10.99.0.0/24` |

## Docker Yerləşdirmə

### docker-compose.yml strukturu
```yaml
services:
  postgres:
    image: postgres:16-alpine
    # Verilənlər bazası

  control-plane:
    build: ...
    network_mode: host      # WireGuard üçün vacib!
    cap_add:
      - NET_ADMIN           # Şəbəkə idarəetməsi
      - SYS_MODULE          # Kernel modulları
    volumes:
      - /etc/wireguard:/etc/wireguard:rw  # Host WireGuard

  web:
    build: ...
    network_mode: host
```

### Vacib Qeydlər
- `network_mode: host` - WireGuard trafikinin düzgün işləməsi üçün
- `/etc/wireguard` mount - Host-un WireGuard konfiqurasiyasına giriş
- `NET_ADMIN` capability - Şəbəkə interfeyslərini idarə etmək üçün

## İnkişaf

### Yerli İnkişaf
```bash
cd server

# Asılılıqları yüklə
go mod download

# Mühit dəyişənlərini təyin et
export DATABASE_URL="postgres://NovusGate:password@localhost:5432/NovusGate?sslmode=disable"
export JWT_SECRET="dev_secret"
export NovusGate_API_KEY="dev_key"
export ADMIN_PASSWORD="admin123"

# İşə sal
go run ./cmd/control-plane serve
```

### Build
```bash
# Binary build
go build -o NovusGate-server ./cmd/control-plane

# Docker build
docker build -f deployments/docker/Dockerfile.control-plane -t NovusGate-server .
```

### Test
```bash
go test ./...
```

## Təhlükəsizlik

1. **JWT Tokenləri** - Hər startup-da yeni admin token yaradılır
2. **API Key** - Bütün API çağırışları üçün tələb olunur
3. **Bcrypt** - Parollar hash-lənir
4. **VPN Arxasında** - Admin panel yalnız wg0 üzərindən əlçatandır
5. **CORS** - Bütün origin-lərə icazə (development üçün)

## Problemlərin Həlli

| Problem | Səbəb | Həll |
|---------|-------|------|
| "wg command not found" | WireGuard quraşdırılmayıb | `apt install wireguard-tools` |
| "permission denied" | NET_ADMIN capability yoxdur | Docker-da `cap_add` yoxla |
| "database connection refused" | PostgreSQL işləmir | Container statusunu yoxla |
| "interface already exists" | wg0 artıq var | `wg-quick down wg0` |
| Peer-lər görünmür | Manager init olmayıb | Server loglarını yoxla |

## Töhfə Vermək

1. **Kod Stili** - `gofmt` və Go idiomlarına əməl edin
2. **Test** - `internal/` üçün unit testlər əlavə edin
3. **Miqrasiya** - Sxem dəyişiklikləri SQL miqrasiya faylları kimi əlavə edilməlidir
4. **Sənədləşdirmə** - Yeni xüsusiyyətlər üçün təlimatları yeniləyin

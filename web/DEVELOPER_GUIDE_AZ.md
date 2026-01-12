# NovusGate Web Dashboard - Developer Təlimatı

## İcmal

NovusGate Web Dashboard, WireGuard mesh VPN şəbəkələrini idarə etmək üçün müasir, responsiv React tətbiqidir. Node idarəçiliyi, şəbəkə monitorinqi və istifadəçi administrasiyası üçün vizual interfeys təqdim edir.

## Texnologiya Yığını

| Texnologiya | Versiya | Məqsəd |
|-------------|---------|--------|
| React | 18.x | UI Framework |
| TypeScript | 5.x | Tip Təhlükəsizliyi |
| Vite | 5.x | Build Aləti & Dev Server |
| Tailwind CSS | 3.x | Stil (Qaranlıq Rejim dəstəyi) |
| React Query | 5.x | Server State İdarəçiliyi |
| Zustand | 4.x | Client State İdarəçiliyi |
| React Router | 6.x | Marşrutlaşdırma |
| Axios | 1.x | HTTP Client |
| Lucide React | - | İkonlar |
| clsx | - | Class Name Utility |

## Qovluq Strukturu

```
web/
├── src/
│   ├── api/
│   │   └── client.ts          # Axios instance, API funksiyaları, React Query hooks
│   ├── components/
│   │   ├── ui.tsx             # Təkrar istifadə edilən UI komponentləri
│   │   ├── Layout.tsx         # Sidebar ilə əsas layout
│   │   ├── CreateNodeModal.tsx    # Yeni peer yaratma formu
│   │   ├── EditNodeModal.tsx      # Peer redaktə formu
│   │   └── ServerConfigModal.tsx  # WireGuard config & QR kod göstəricisi
│   ├── pages/
│   │   ├── Dashboard.tsx      # İcmal statistikası
│   │   ├── Networks.tsx       # Şəbəkə idarəçiliyi (CRUD)
│   │   ├── Nodes.tsx          # Peer/Node idarəçiliyi
│   │   └── Settings.tsx       # İstifadəçi & şifrə idarəçiliyi
│   ├── store/
│   │   └── index.ts           # Zustand store (auth, theme, sidebar)
│   ├── types/
│   │   └── index.ts           # TypeScript interfeysləri
│   ├── App.tsx                # Router & Auth wrapper
│   └── main.tsx               # React DOM giriş nöqtəsi
├── public/                    # Statik aktivlər
├── index.html                 # HTML giriş nöqtəsi
├── nginx.conf                 # Production HTTPS konfiqurasiyası
├── Dockerfile                 # Multi-stage Docker build
├── vite.config.ts             # Vite konfiqurasiyası
├── tailwind.config.js         # Tailwind CSS konfiqurasiyası
└── tsconfig.json              # TypeScript konfiqurasiyası
```

## Əsas Komponentlər

### API Client (`src/api/client.ts`)

Axios və React Query ilə mərkəzləşdirilmiş API qatı:

```typescript
// Interceptor-larla Axios instance
const axiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api/v1',
});

// Auth header əlavəsi
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  const apiKey = localStorage.getItem('apiKey');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  if (apiKey) config.headers['X-API-Key'] = apiKey;
  return config;
});

// API Funksiyaları
export const api = {
  login: (username: string, password: string) => Promise<LoginResponse>,
  getNodes: () => Promise<Node[]>,
  createNode: (data: CreateNodeRequest) => Promise<Node>,
  updateNode: (id: string, data: UpdateNodeRequest) => Promise<Node>,
  deleteNode: (id: string) => Promise<void>,
  getNodeConfig: (id: string) => Promise<string>,
  getNodeQrCode: (id: string) => Promise<Blob>,
  // ... digər endpoint-lər
};

// React Query Hooks
export const useNodes = () => useQuery({ queryKey: ['nodes'], queryFn: api.getNodes });
export const useCreateNode = () => useMutation({ mutationFn: api.createNode });
```

### State İdarəçiliyi (`src/store/index.ts`)

Client-side state üçün Zustand store:

```typescript
interface AppState {
  // Auth
  isAuthenticated: boolean;
  user: User | null;
  login: (user: User, token: string) => void;
  logout: () => void;
  
  // UI
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
}
```

### UI Komponentləri (`src/components/ui.tsx`)

Təkrar istifadə edilən komponent kitabxanası:

| Komponent | Props | Təsvir |
|-----------|-------|--------|
| `Button` | variant, size, loading, disabled | Əsas əməliyyat düyməsi |
| `Card` | padding, className | Konteyner kartı |
| `Badge` | variant (success/warning/danger/info) | Status nişanları |
| `StatusIndicator` | status, showLabel | Online/offline göstəricisi |
| `Input` | label, error, helperText | Form input |
| `Select` | label, options, error | Dropdown seçim |
| `Modal` | isOpen, onClose, title, size | Dialoq modalı |
| `Table` | columns, data, onRowClick, loading | Data cədvəli |
| `StatCard` | title, value, icon, change | Statistika kartı |
| `EmptyState` | icon, title, description, action | Boş vəziyyət placeholder |

### Səhifə Komponentləri

#### Dashboard (`src/pages/Dashboard.tsx`)
- Ümumi/online/offline node saylarını göstərir
- Son aktivlik siyahısını göstərir
- `StatCard` komponentlərindən istifadə edir

#### Nodes (`src/pages/Nodes.tsx`)
- Bütün peer-ləri status, IP, transfer statistikası ilə siyahılayır
- Yaratma/Redaktə/Silmə əməliyyatları
- Config yükləmə & QR kod generasiyası
- Filtrasiya və axtarış

#### Networks (`src/pages/Networks.tsx`)
- Şəbəkə CRUD əməliyyatları
- Subnet konfiqurasiyası
- Node təyinatı

#### Settings (`src/pages/Settings.tsx`)
- Şifrə dəyişmə formu
- İstifadəçi idarəçiliyi (yalnız admin)
- Dashboard istifadəçilərini yaratma/silmə

#### Firewall (`src/pages/Firewall.tsx`)

Çoxlu tab-lı hərtərəfli firewall idarəetmə səhifəsi:

**Komponent Strukturu:**
```typescript
// Əsas komponent
export const Firewall: React.FC

// Tab komponentləri
const OverviewTab: React.FC<OverviewTabProps>
const HostRulesTab: React.FC<HostRulesTabProps>
const OpenPortsTab: React.FC<OpenPortsTabProps>
const VPNRulesTab: React.FC<VPNRulesTabProps>
const BlockedIPsTab: React.FC<BlockedIPsTabProps>

// Modal komponent
const VPNRuleModal: React.FC<VPNRuleModalProps>
```

**İstifadə Olunan API Hook-ları:**
```typescript
// Host Firewall
useFirewallRules()      // GET /api/v1/firewall/rules
useOpenPort()           // POST /api/v1/firewall/open-port
useClosePort()          // POST /api/v1/firewall/close-port
useBlockIP()            // POST /api/v1/firewall/block-ip
useAllowIP()            // POST /api/v1/firewall/allow-ip
useDeleteFirewallRule() // DELETE /api/v1/firewall/rules
useResetFirewall()      // POST /api/v1/firewall/reset

// VPN Firewall
useVPNFirewallRules()       // GET /api/v1/vpn-firewall/rules
useCreateVPNFirewallRule()  // POST /api/v1/vpn-firewall/rules
useUpdateVPNFirewallRule()  // PUT /api/v1/vpn-firewall/rules/:id
useDeleteVPNFirewallRule()  // DELETE /api/v1/vpn-firewall/rules/:id
useApplyVPNFirewallRules()  // POST /api/v1/vpn-firewall/apply
```

**TypeScript İnterfeysləri:**
```typescript
interface FirewallRule {
  number: number;
  target: string;
  protocol: string;
  source: string;
  destination: string;
  port?: string;
  in_interface?: string;
  out_interface?: string;
  chain: string;
  protected: boolean;
}

interface VPNFirewallRule {
  id: string;
  name: string;
  description?: string;
  source_type: VPNEndpointType;
  source_network_id?: string;
  source_network_name?: string;
  source_node_id?: string;
  source_node_name?: string;
  source_ip?: string;
  dest_type: VPNEndpointType;
  dest_network_id?: string;
  dest_network_name?: string;
  dest_node_id?: string;
  dest_node_name?: string;
  dest_ip?: string;
  protocol: VPNFirewallProtocol;
  port?: string;
  action: VPNFirewallAction;
  priority: number;
  enabled: boolean;
}

type VPNEndpointType = 'any' | 'network' | 'node' | 'custom';
type VPNFirewallProtocol = 'all' | 'tcp' | 'udp' | 'icmp';
type VPNFirewallAction = 'accept' | 'drop' | 'reject';
```

**Əsas Xüsusiyyətlər:**
- Tab əsaslı naviqasiya (Overview, Host Rules, Open Ports, VPN Rules, Blocked IPs)
- Qorunan port aşkarlanması (SSH, WireGuard, API)
- VPN qayda prioritet sistemi
- VPN qaydaları dəyişdikdə avtomatik AllowedIPs sinxronizasiyası
- Real vaxt qayda tətbiqi

### Modal Komponentləri

#### CreateNodeModal
- Peer adı input
- Bitmə vaxtı seçimləri: Daimi, 1 saat, 1 gün, 1 həftə, Xüsusi
- Serverdə WireGuard açarlarını avtomatik generasiya edir

#### EditNodeModal
- Ad, status, bitmə vaxtını redaktə etmək
- Cihaz metadata-sı (OS, arch, hostname)
- Vaxt limitlərini uzatmaq və ya silmək

#### ServerConfigModal
- Multi-tab interfeys:
  - **General**: Config mətni + QR kod
  - **Windows**: Yükləmə linki + təlimatlar
  - **macOS**: App Store linki + təlimatlar
  - **Linux**: Bir sətirlik quraşdırma skripti + manual addımlar
  - **Docker**: Docker run əmri

## İnkişaf Mühitinin Qurulması

### Tələblər
- Node.js 18+
- npm və ya yarn

### Mühit Dəyişənləri

`.env` faylı yaradın:
```bash
VITE_API_URL=http://localhost:8080/api/v1
VITE_API_KEY=your-api-key  # İnkişaf üçün isteğe bağlı
```

### Yerli İşə Salma

```bash
# Asılılıqları quraşdırın
cd web
npm install

# Development server başladın
npm run dev
```

Giriş: `http://localhost:3000`

### API Proxy

Vite `/api` sorğularını backend-ə yönləndirir:

```typescript
// vite.config.ts
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
    },
  },
},
```

## Production Build

### Build Əmri
```bash
npm run build
```

Çıxış: statik fayllarla `dist/` qovluğu

### Docker Build

Multi-stage Dockerfile:

```dockerfile
# Mərhələ 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Mərhələ 2: Nginx ilə servis
FROM nginx:alpine
RUN apk add --no-cache openssl
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Öz-imzalı SSL sertifikatı generasiya et
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=AZ/ST=Baku/L=Baku/O=NovusGate/CN=NovusGate.local"

EXPOSE 3007
CMD ["nginx", "-g", "daemon off;"]
```

### Nginx Konfiqurasiyası

```nginx
server {
    listen 3007 ssl;
    server_name _;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /usr/share/nginx/html;
    index index.html;

    # SPA marşrutlaşdırması
    location / {
        try_files $uri $uri/ /index.html;
    }

    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
}
```

## TypeScript Tipləri

### Əsas İnterfeysler (`src/types/index.ts`)

```typescript
interface Node {
  id: string;
  name: string;
  public_key: string;
  endpoint: string;
  allowed_ips: string;
  status: 'online' | 'offline' | 'pending' | 'expired';
  last_handshake: string;
  transfer_rx: number;
  transfer_tx: number;
  expires_at?: string;
  node_info?: {
    os: string;
    arch: string;
    hostname: string;
  };
  created_at: string;
  updated_at: string;
}

interface Network {
  id: string;
  name: string;
  subnet: string;
  description?: string;
  created_at: string;
}

interface User {
  id: string;
  username: string;
  role: 'admin' | 'user';
  created_at: string;
}
```

## Stil Qaydaları

### Tailwind CSS
- Bütün stillər üçün utility class-lardan istifadə edin
- Qaranlıq rejim: `dark:` prefiksi
- Responsiv: `sm:`, `md:`, `lg:`, `xl:` breakpoint-ləri

### Rəng Palitrası
- Əsas: `blue-600` / `blue-500`
- Uğur: `green-500`
- Xəbərdarlıq: `yellow-500`
- Təhlükə: `red-500`
- Arxa fon: `white` / `gray-900` (qaranlıq)

### Qaranlıq Rejim
```tsx
// Store-da keçid
const { theme, setTheme } = useStore();

// Root-a tətbiq et
<html className={theme === 'dark' ? 'dark' : ''}>
```

## Autentifikasiya Axını

1. İstifadəçi login formu göndərir
2. `api.login()` məlumatları `/api/v1/auth/login`-ə göndərir
3. Server JWT token qaytarır
4. Token `localStorage`-da saxlanılır
5. Axios interceptor bütün sorğulara `Authorization: Bearer <token>` əlavə edir
6. Zustand store `isAuthenticated` state-ni yeniləyir
7. Router Dashboard-a yönləndirir

## Xəta İdarəçiliyi

```typescript
// React Query xəta idarəçiliyi
const { data, error, isLoading } = useNodes();

if (error) {
  return <div className="text-red-500">{error.message}</div>;
}

// 401 üçün Axios interceptor
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
```

## Test

```bash
# Testləri işə sal
npm run test

# Tip yoxlaması
npm run type-check

# Linting
npm run lint
```

## Töhfə Vermək

1. TypeScript strict mode-a əməl edin
2. Hooks ilə funksional komponentlər istifadə edin
3. Komponentləri kiçik və fokuslanmış saxlayın
4. Server state üçün React Query istifadə edin
5. Client state üçün Zustand istifadə edin
6. Qaranlıq rejim uyğunluğunu qoruyun
7. Responsiv dizaynı təmin edin

## Dəstək

[Ali Zeynalli](https://github.com/Ali7Zeynalli) tərəfindən hazırlanıb

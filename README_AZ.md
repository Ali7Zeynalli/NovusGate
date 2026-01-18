# NovusGate

[![GitHub stars](https://img.shields.io/github/stars/Ali7Zeynalli/NovusGate?style=social)](https://github.com/Ali7Zeynalli/NovusGate/stargazers)
[![Lisenziya](https://img.shields.io/badge/Lisenziya-Apache_2.0-blue.svg)](LICENSE)
[![WireGuard](https://img.shields.io/badge/Protocol-WireGuard-88171A.svg)](https://www.wireguard.com/)
[![VPN Type](https://img.shields.io/badge/VPN%20Tipi-Uzaqdan%20Giri%C5%9F-blue.svg)](#-vpn-tipi)

🚀 **Öz şəxsi VPN şəbəkənizi qurun — SaaS asılılığı və ya ağrılı konfiqurasiyalar olmadan.**

**NovusGate** — **WireGuard®** protokolu üzərində qurulmuş, müasir, tamamı ilə özünü idarə edən (self-hosted) **VPN idarəetmə panelidir**.
Bu sistem, tək bir veb paneldən idarə olunan təmiz **Hub-and-Spoke (Mərkəz və Budaq) arxitekturası** vasitəsilə serverləri, bulud instansiyalarını və şəxsi cihazları təhlükəsiz şəkildə birləşdirməyə imkan verir.

İstər istehsalat (production) infrastrukturunu idarə edin, istərsə də sadəcə şəxsi şəbəkənizə tam sahib olmaq istəyin — **NovusGate sizə aydınlıq, təhlükəsizlik və nəzarət bəxş edir**.

![NovusGate Dashboard](web/public/novusgate_banner.png)

---

## ⚠️ Vacib: NovusGate Nədir (və Nə Deyil)

**NovusGate "IP-ni gizlət" və ya "geo-məhdudiyyətləri keç" tipli VPN DEYİL.**

Bu, aşağıdakılar üçün nəzərdə tutulmuş **şəxsi şəbəkə infrastruktur alətidir**:
- ✅ Serverlər arası təhlükəsiz kommunikasiya
- ✅ Daxili xidmətlərə uzaqdan giriş
- ✅ Paylanmış infrastrukturu birləşdirmək
- ✅ Etibarlı şəxsi şəbəkələr qurmaq

**Trafik Yönləndirməsi:**
- Yalnız VPN subnet-lərinə (məs., `10.x.x.x`) gedən trafik tuneldən keçir
- Adi internet trafikiniz (YouTube, Google və s.) birbaşa ISP-nizdən keçir
- Buna **Split Tunneling** deyilir — səmərəli və məqsədyönlü

Əgər bütün trafikinizi gizlətmək üçün "full tunnel" VPN lazımdırsa, NovusGate sizin üçün uyğun alət deyil. Bu məqsəd üçün kommersiya VPN xidmətlərindən istifadə edin.

---

## 🎯 NovusGate Hansı Problemi Həll Edir?

**Ssenari:** Bir yerdə serveriniz var (cloud, ev, ofis) amma:
- ❌ Ona qoşulmaq üçün statik IP-niz yoxdur
- ❌ Serverin IP-sini birbaşa internetə açmaq istəmirsiniz
- ❌ NAT/Firewall birbaşa əlaqəni qeyri-mümkün edir

**NovusGate ilə Həll:**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Sizin Server  │     │  NovusGate Hub  │     │ Sizin Komputer  │
│ (Statik IP yox) │     │   (Cloud VPS)   │     │   (Ev/Ofis)     │
│                 │     │                 │     │                 │
│   10.10.10.2    │────▶│   10.10.10.1    │◀────│   10.10.10.3    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                     ▲                     │
         └──────── Hər ikisi Hub-a qoşulur ─────────┘
```

Hər iki cihaz NovusGate-ə qoşulduqdan sonra:
- ✅ Onlar bir-birini **eyni lokal şəbəkədə** kimi görür
- ✅ Serveriniz `10.10.10.2` olur — həmişə əlçatan
- ✅ Komputeriniz `10.10.10.3` olur — SSH, RDP və ya istənilən xidmətə qoşula bilər
- ✅ Port yönləndirmə lazım deyil
- ✅ Statik IP tələb olunmur
- ✅ NAT, firewall arxıasında, harədə olsa işləyir

**Real nümunə:**
```bash
# Komputeriniizdən (10.10.10.3), serverə qoşulun:
ssh user@10.10.10.2

# Serverdə işləyən veb xidmətə daxil olun:
curl http://10.10.10.2:8080
```

Bu, bütün cihazlarınızın eyni LAN-da olması kimidir — fiziki olaraq harada olmalarından asılı olmayaraq.

---

## ✨ Niyə NovusGate?

Bu gün mövcud olan şəxsi şəbəkə həllərinin əksəriyyəti ya:
- ❌ "Qara qutu" kimi işləyən SaaS həlləridir
- ❌ Böyük miqyasda idarə edilməsi çətindir
- ❌ Kiçik komandalar üçün həddindən artıq mürəkkəbdir
- ❌ Ya da öz serverində qurmaq (self-host) çox ağrılıdır

**NovusGate fərqli olmaq üçün yaradılıb.**

O, diqqəti bunlara yönəldir:
- **Rahatlıqdan öncə Sahiblik**
- **Mürəkkəblikdən öncə Sadəlik**
- **Mücərrədlikdən öncə Şəffaflıq**

Onu siz işlədirsiniz.
Siz idarə edirsiniz.
Sizin şəbəkəniz — sizin qaydalarınız.

---

## 🚀 Əsas Xüsusiyyətlər

- **Çoxlu Şəbəkə Arxitekturası**
  Hər birinin öz WireGuard interfeysi, subnet-i və portu olan çoxlu izolyasiya edilmiş VPN şəbəkələri yaradın.

- **Hub-and-Spoke Arxitekturası**
  Qovşaqlar arasında trafikin mərkəzi server vasitəsilə təhlükəsiz yönləndirilməsi.

- **Müasir Veb Dashboard**
  Şəbəkələri, qovşaqları idarə etmək, trafiki izləmək və VPN-ə nəzarət etmək üçün React əsaslı gözəl interfeys.

- **Bir Kliklə Quraşdırıcı**
  Xüsusi Docker əsaslı quraşdırıcı (installer) ilə NovusGate-i asanlıqla yerləşdirin və yeniləyin.

- **Təhlükəsiz və Ağıllı Yeniləmələr**
  Konfiqurasiyanı və ya şəbəkə vəziyyətini itirmədən sisteminizi yeniləyin.

- **Defolt Olaraq Təhlükəsiz**
  WireGuard kriptoqrafiyası, JWT autentifikasiyası və daxili kommunikasiya üçün API açarları.

- **Çox Platformalı Client Dəstəyi**
  Mobil üçün QR kodlar, desktop üçün konfiq yükləmələri, Linux üçün bir sətirlik quraşdırma skriptləri.

- **Server Monitorinq Paneli**
  Əsas dashboard-da real vaxt rejimində CPU, RAM, Disk istifadəsi və sistem uptime göstəricisi.

- **Fail2Ban İnteqrasiyası**
  SSH brute-force hücumlarından qorunma, jail idarəetməsi, bloklanmış IP-lərin görüntülənməsi və bir kliklə blokdan çıxarma.

- **Firewall İdarəetməsi**
  Hərtərəfli host firewall (iptables) və VPN şəbəkələrarası firewall ilə VPN şəbəkələri arasında trafik nəzarəti.

- **Vahid Şəbəkə İcmalı**
  Dashboard bütün şəbəkələri birləşdirilmiş ümumi statistika ilə, həmçinin hər şəbəkə üzrə ayrıca göstəricilərlə göstərir.

---

## 📡 VPN Tipi

**NovusGate Client-əsaslı Arxitektura ilə Uzaqdan Giriş VPN-dir (Remote Access VPN).**

| VPN Tipi | NovusGate? | Təsvir |
|----------|------------|--------|
| ☁️ Cloud VPN | ⚠️ | AWS/Azure VPN Gateway kimi idarə olunan xidmət deyil. NovusGate istənilən cloud və ya yerli serverdə quraşdırıla bilər |
| 🔐 IPsec VPN | ❌ | IPsec əvəzinə WireGuard protokolu istifadə edir |
| 🌐 SSL VPN | ❌ | Browser-əsaslı deyil, WireGuard client tələb edir |
| 💻 **Client-əsaslı VPN** | ✅ | WireGuard client proqramı tələb edir |
| 🏢 Site-to-Site VPN | ⚠️ | Node-lar arası əlaqə ilə mümkündür |
| 📡 **Uzaqdan Giriş VPN** | ✅ | Əsas istifadə halı |

**Əsas Xüsusiyyətlər:**
- **Protokol:** WireGuard (müasir, sürətli, təhlükəsiz)
- **Arxitektura:** Hub-and-Spoke (mərkəzləşdirilmiş idarəetmə)
- **Tunelleme:** Şifrlənmiş etibarlı tunel, Split Tunneling ilə
- **Yerləşdirmə:** Cloud-da (istənilən provider) və ya yerli serverdə
- **Client-lər:** Mobil (QR), Desktop (.conf), Linux (skriptlər)

---

## 👥 NovusGate Kimlər Üçündür?

- **Sistem Adminləri** — serverlər və məlumat mərkəzləri arasında təhlükəsiz giriş təmin edənlər
- **DevOps Mühəndisləri** — infrastrukturu müxtəlif mühitlər (environments) arasında birləşdirənlər
- **Proqramçılar** — daxili və ya self-hosted platformalar quranlar
- **Məxfilik sevənlər** — öz VPN quruluşuna tam nəzarət etmək istəyənlər

Əgər **self-hosting, təhlükəsizlik və sadəliyə** dəyər verirsinizsə, NovusGate sizin üçündür.

---

## 🧠 Necə İşləyir? (Qısa İzah)

1. **Mərkəzi server** idarəetmə paneli (control plane) rolunu oynayır.
2. Unikal subnet-lərlə (10.x.x.0/24) **izolyasiya edilmiş şəbəkələr** yaradın.
3. Cihazlar qeydiyyatdan keçir və təhlükəsiz şəkildə autentifikasiya olunur.
4. WireGuard tunelləri avtomatik olaraq qurulur.
5. Trafik mərkəzi server üzərindən təhlükəsiz şəkildə yönləndirilir.

Gizli sehir yoxdur.
Vendor asılılığı (lock-in) yoxdur.
Sadəcə təmiz şəbəkəçilik.

---

## 📂 Sistem Memarlığı

NovusGate maksimum çeviklik və dayanıqlılıq üçün idarəetmə, interfeys və yerləşdirməni ayıran **modul sistem** kimi dizayn edilib.

```
+-------------------------------------------------------------+
|                     NovusGate Server                        |
|  +-------------+  +-------------+  +-------------+          |
|  |  Şəbəkə 1   |  |  Şəbəkə 2   |  |  Şəbəkə N   |          |
|  |  wg0:51820  |  |  wg1:51821  |  |  wgN:518XX  |          |
|  | 10.10.0.0/24|  | 10.20.0.0/24|  | 10.XX.0.0/24|          |
|  +------+------+  +------+------+  +------+------+          |
|         |                |                |                 |
|  +------+----------------+----------------+------+          |
|  |              REST API (Go Backend)            |          |
|  |                 PostgreSQL DB                 |          |
|  +-----------------------------------------------+          |
+-------------------------------------------------------------+
                            |
              +-------------+-------------+
              |             |             |
         +----+----+  +----+----+  +----+----+
         | Client  |  | Client  |  | Client  |
         | (Telefon)|  |(Notebook)|  | (Server)|
         +---------+  +---------+  +---------+
```

### 1. Server (Backend)
📁 `./server`

**Go** dilində yazılmış əsas məntiq.
WireGuard interfeyslərini, PostgreSQL verilənlər bazasını idarə edir və REST API təqdim edir.

- **Developer Guide:** `./server/DEVELOPER_GUIDE_AZ.md`
- **User Guide:** `./server/USER_GUIDE_AZ.md`

---

### 2. Web Dashboard (Frontend)
📁 `./web`

**React**, **TypeScript** və **Tailwind CSS** ilə qurulmuş inzibatçı interfeysi.

- **Developer Guide:** `./web/DEVELOPER_GUIDE_AZ.md`
- **User Guide:** `./web/USER_GUIDE_AZ.md`

---

### 3. Installer (Quraşdırıcı)
📁 `./installer`

Linux serverlərində SSH vasitəsilə yerləşdirməni sadələşdirmək üçün müstəqil **Node.js** aləti.

- **Developer Guide:** `./installer/DEVELOPER_GUIDE_AZ.md`
- **User Guide:** `./installer/USER_GUIDE_AZ.md`

---

> 🇺🇸 **English Documentation**
> Refer to [README.md](./README.md) for the English version.

---

## ⚡ Tez Başlanğıc

### Tələblər

**Yerli kompüterinizdə:**
- Docker və Docker Compose quraşdırılmış olmalıdır

**Uzaq serverinizdə:**
- Linux server (Ubuntu 20.04 / 22.04 tövsiyə olunur)
- Root və ya sudo səlahiyyətli SSH girişi
- Açıq portlar: 22 (SSH), 51820+ (WireGuard üçün UDP), 8080 (API)

---

### Quraşdırma Prosesi (Addım-Addım)

> **Qeyd:** Bu proses **NovusGate Installer** (Quraşdırma Paneli) -ni işə salır. Bu panel vasitəsilə siz serveri, məlumat bazasını və VPN şəbəkəsini asanlıqla quraşdıra bilərsiniz.

#### Addım 1: Repozitoriyanı Klonlayın

```bash
git clone https://github.com/Ali7Zeynalli/NovusGate.git
cd NovusGate
```

#### Addım 2: Installer-i Başladın

```bash
cd installer
docker-compose up -d --build
```

#### Addım 3: Installer Veb İnterfeysini Açın

Brauzerdə bu ünvanı açın:
```
http://localhost:3017
```

#### Addım 4: Uzaq Serverə Qoşulun

Installer interfeysində server məlumatlarınızı daxil edin:

| Sahə | Təsvir |
|------|--------|
| **Host** | Serverinizin IP ünvanı (məs., `203.0.113.50`) |
| **Port** | SSH portu (defolt: `22`) |
| **Username** | SSH istifadəçi adı (məs., `root` və ya `ubuntu`) |
| **Password** | SSH şifrəsi və ya SSH açarı istifadə edin |

SSH bağlantısı qurmaq üçün **Connect** düyməsini sıxın.

#### Addım 5: Quraşdırmanı Konfiqurasiya Edin

Qoşulduqdan sonra quraşdırma parametrlərini təyin edin:

| Parametr | Təsvir |
|----------|--------|
| **Admin Username** | Dashboard giriş istifadəçi adı (defolt: `admin`) |
| **Admin Password** | Dashboard giriş şifrəsi (avtomatik yaradılır və ya özünüz təyin edin) |
| **Server Endpoint** | VPN bağlantıları üçün serverinizin açıq IP-si |
| **Admin CIDR** | Admin şəbəkə subnet-i (defolt: `10.99.0.0/24`) |
| **API Key** | Daxili API təhlükəsizlik açarı (avtomatik yaradılır) |

#### Addım 6: Quraşdırmanı Başladın

**Install NovusGate Server** düyməsini sıxın.

Installer aşağıdakıları edəcək:
1. ✅ Sistem paketlərini yeniləyəcək
2. ✅ Docker və Docker Compose quraşdıracaq
3. ✅ WireGuard quraşdıracaq
4. ✅ Fail2Ban quraşdıracaq (SSH qorunması)
5. ✅ NovusGate repozitoriyasını klonlayacaq
6. ✅ Environment dəyişənlərini konfiqurasiya edəcək
7. ✅ Docker konteynerləri build edib başladacaq
8. ✅ Admin VPN şəbəkəsi yaradacaq
9. ✅ Admin VPN konfiqurasiyası generasiya edəcək

#### Addım 7: Giriş Məlumatlarınızı Saxlayın

Quraşdırma bitdikdən sonra installer göstərəcək:

```
╔════════════════════════════════════════════╗
║         QURAŞDIRMA TAMAMLANDI!             ║
╠════════════════════════════════════════════╣
║  Admin Username: admin                     ║
║  Admin Password: xxxxxxxxxxxxxxxx          ║
║                                            ║
║  Dashboard URL: https://10.99.0.1:3007     ║
║  (Yalnız VPN vasitəsilə əlçatandır)        ║
╚════════════════════════════════════════════╝
```

⚠️ **VACİB:** Bu məlumatları dərhal saxlayın! Bir daha göstərilməyəcək.

#### Addım 8: Admin VPN Konfiqini Yükləyin

Installer sizə admin VPN konfiqurasiyasını təqdim edir:
- **QR Kod** - WireGuard mobil tətbiqi ilə skan edin
- **Download .conf** - Desktop WireGuard client üçün
- **Copy Config** - Manual konfiqurasiya

#### Addım 9: Admin VPN-ə Qoşulun

1. Cihazınıza WireGuard client quraşdırın
2. Admin konfiqurasiyasını import edin
3. VPN bağlantısını aktivləşdirin
4. Bağlantını yoxlayın (IP `10.99.0.2` kimi olmalıdır)

#### Addım 10: Dashboard-a Daxil Olun

VPN-ə qoşulduqdan sonra açın:
```
https://10.99.0.1:3007
```

Addım 7-dəki admin məlumatları ilə daxil olun.

🎉 **Təbrik edirik!** NovusGate quraşdırıldı və istifadəyə hazırdır.

---

### Quraşdırmadan Sonra

Dashboard-a daxil olduqdan sonra edə bilərsiniz:
- Əlavə VPN şəbəkələri yaratmaq
- Şəbəkələrə node/client əlavə etmək
- Server resurslarını izləmək
- Fail2Ban təhlükəsizliyini idarə etmək
- Trafik statistikasını görmək

---

### Texniki Detallar: Installer Nə Edir?

Installer uzaq Linux serverinizdə quraşdırmanı avtomatlaşdırır. Arxa planda baş verən proseslər bunlardır:

1.  **Sistem Yeniləmələri**: Paketlərin təzə olduğundan əmin olmaq üçün `apt-get update` icra edir.
2.  **Asılılıqlar**: `docker`, `docker-compose`, `wireguard` və `fail2ban` quraşdırır.
3.  **Fayl Yerləşimi**:
    -   Quraşdırma Qovluğu: `/opt/NovusGate`
    -   Admin VPN Konfiqurasiyası: `/opt/NovusGate/admin-vpn.conf`
4.  **Təhlükəsizlik Quraşdırması**:
    -   Verilənlər bazası, JWT və API açarları üçün təhlükəsiz təsadüfi sirrlər (secrets) yaradır.
    -   SSH qorunması üçün `fail2ban` jail-ini konfiqurasiya edir.
    -   Admin Şəbəkəsi üçün `wg0` WireGuard interfeysini qurur.
5.  **Xidmətlərin Başladılması**:
    -   `/opt/NovusGate/server/deployments/docker/` və `/opt/NovusGate/web/` qovluqlarında `.env` faylları yaradır.
    -   `docker-compose up -d` istifadə edərək xidmətləri işə salır.

Bu, əl ilə konfiqurasiya olmadan standartlaşdırılmış, təhlükəsiz və istehsalata hazır (production-ready) bir mühit təmin edir.

---

### Lokal İnkişaf / Manual İşə Salma

Əgər NovusGate-i quraşdırıcı ("installer wizard") olmadan, inkişaf (development) və ya test məqsədilə lokal kompüterinizdə işə salmaq istəyirsinizsə:

1. Docker deployment qovluğuna keçid edin:
   ```bash
   cd server/deployments/docker
   ```

2.  **Mühiti Konfiqurasiya Edin (.env)**:
    ```bash
    cp .env.example .env
    # .env faylını açın və ən azı ADMIN_PASSWORD təyin edin
    nano .env
    ```

3.  **Xidmətləri başladın**:
    ```bash
    docker-compose up -d --build
    ```

   Bu əmr aşağıdakıları başladacaq:
   - **PostgreSQL** (Məlumat bazası)
   - **Control Plane** (Backend API - port 8080)
   - **Web Dashboard** (Frontend - port 3007)

3. Dashboard-a daxil olun: `http://localhost:3007`

> **Qeyd:** Tam VPN funksionallığı üçün WireGuard kernel modullarına malik Linux mühiti tələb olunur. Windows/Mac əməliyyat sistemlərində bəzi VPN funksiyaları məhdud ola bilər, lakin UI və API tam işlək vəziyyətdə olacaq.

---

### Əl ilə Quraşdırma (Manual Production)

İstehsalat (production) mühitində manual quraşdırmanı üstün tutan təcrübəli istifadəçilər üçün:
👉 **[Server İstifadəçi Təlimatı](./server/USER_GUIDE_AZ.md)**

---

## 🌐 Şəbəkə İdarəçiliyi

NovusGate **çoxlu izolyasiya edilmiş şəbəkələri** dəstəkləyir:

| Xüsusiyyət | Təsvir |
|------------|--------|
| **İzolyasiya Edilmiş Subnet-lər** | Hər şəbəkənin öz CIDR-i var (məs., 10.10.0.0/24, 10.20.0.0/24) |
| **Xüsusi İnterfeyslər** | Avtomatik WireGuard interfeys təyinatı (wg0, wg1, wg2...) |
| **Unikal Portlar** | Hər şəbəkə fərqli UDP portunda dinləyir (51820, 51821...) |
| **Müstəqil Node-lar** | Node-lar müəyyən şəbəkələrə aiddir və digərlərindən izolyasiya edilib |

### Şəbəkə Yaratmaq

1. Dashboard-da **Networks** səhifəsinə keçin
2. **Create Network** düyməsinə klikləyin
3. Ad və CIDR aralığı daxil edin (məs., `10.50.0.0/24`)
4. Sistem avtomatik olaraq interfeys və port təyin edir

---

## 🛡️ Təhlükəsizlik Qeydləri

* Quraşdırıcı **unikal giriş məlumatları** yaradır — onları dərhal yadda saxlayın.
* UDP portlarının **51820+** açıq olduğundan əmin olun (hər şəbəkə üçün bir port).
* Admin dashboard defolt olaraq **VPN arxasında gizlidir**.
* İstehsalat (production) mühitində Web Dashboard-u **Nginx və ya Caddy (SSL ilə)** arxasında işlədin.
* **Fail2Ban** avtomatik quraşdırılır və SSH-ı qorumaq üçün konfiqurasiya edilir (3 uğursuz cəhd = 1 saat blok).

Təhlükəsizlik seçim deyil — bu, standartdır.

---

## 📊 Server Monitorinqi

NovusGate daxili server monitorinqi ilə gəlir:

| Göstərici | Təsvir |
|-----------|--------|
| **CPU İstifadəsi** | Real vaxt rejimində prosessor yüklənməsi faizi |
| **RAM İstifadəsi** | İstifadə olunan/ümumi yaddaş göstəricisi |
| **Disk İstifadəsi** | Kök bölməsi üçün yaddaş istifadəsi |
| **Uptime** | Son yenidən başlatmadan bəri serverin işləmə müddəti |

Bütün göstəricilər əsas Dashboard-da göstərilir və avtomatik yenilənir.

---

## 🔒 Fail2Ban İdarəetməsi

Serverinizi brute-force hücumlarından qoruyun:

| Xüsusiyyət | Təsvir |
|------------|--------|
| **Jail Statusu** | Aktiv jail-ləri (SSH və s.) və onların konfiqurasiyasını görün |
| **Bloklanmış IP-lər** | Hər jail üzrə hazırda bloklanmış IP ünvanlarını görün |
| **Blok Statistikası** | Ümumi bloklar, cari bloklar, uğursuz cəhdlər |
| **Bir Kliklə Blokdan Çıxarma** | Veb interfeysdən IP ünvanlarını dərhal blokdan çıxarın |
| **Log Görüntüləyicisi** | Fail2Ban loglarını əməliyyat filtri ilə nəzərdən keçirin |

Dashboard-da **Security → Fail2Ban** bölməsindən daxil olun.

---

## 🔥 Firewall İdarəetməsi

NovusGate hərtərəfli firewall idarəetmə sistemi ilə gəlir:

### Host Firewall (iptables)

| Xüsusiyyət | Təsvir |
|------------|--------|
| **Açıq Portlar** | Serverdəki açıq portları görün və idarə edin |
| **IP Bloklama** | Müəyyən IP ünvanlarını və ya CIDR aralıqlarını bloklayın |
| **IP İcazə** | Etibarlı IP ünvanlarını ağ siyahıya əlavə edin |
| **Chain İdarəetməsi** | INPUT, OUTPUT, FORWARD chain qaydalarını görün |
| **Qorunan Portlar** | SSH, WireGuard və API portları təsadüfi bağlanmadan qorunur |
| **Qaydaları Export Et** | Cari firewall qaydalarını ehtiyat nüsxə üçün yükləyin |
| **Firewall Sıfırla** | Defolt NovusGate firewall konfiqurasiyasını bərpa edin |

### VPN Firewall (Şəbəkələrarası Qaydalar)

VPN şəbəkələri arasında trafik axınını idarə edin:

| Xüsusiyyət | Təsvir |
|------------|--------|
| **Şəbəkədən-Şəbəkəyə Qaydalar** | Müxtəlif VPN şəbəkələri arasında trafikə icazə verin və ya bloklayın |
| **Node-Spesifik Qaydalar** | Müəyyən node-lar üçün qaydalar yaradın |
| **Protokol Filtri** | TCP, UDP, ICMP və ya bütün protokollar üzrə filtrləyin |
| **Port Əsaslı Qaydalar** | Müəyyən portlara və ya port aralıqlarına icazə verin/bloklayın |
| **Prioritet Sistemi** | Qaydalar prioritet sırasına görə işlənir (aşağı = yüksək prioritet) |
| **Avtomatik AllowedIPs** | Client konfiqləri avtomatik olaraq icazə verilmiş hədəf şəbəkələri əhatə edir |

**VPN Firewall Necə İşləyir:**
```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│ Mənbə Node  │ ──► │   VPN Server    │ ──► │ Hədəf Node  │
│ (10.10.0.2) │     │ FORWARD chain   │     │ (10.20.0.5) │
└─────────────┘     │ VPN Qaydaları   │     └─────────────┘
                    └─────────────────┘
```

Bütün VPN trafiki server üzərindən keçir. VPN firewall qaydaları serverin FORWARD chain-ini idarə edir və hansı trafikin şəbəkələr arasında yönləndirilə biləcəyini müəyyən edir.

**İstifadə Nümunələri:**
- Ofis şəbəkəsinin (10.10.0.0/24) admin panelinə (10.99.0.1) girişinə icazə vermək
- Development şəbəkəsinin production serverlərə girişini bloklamaq
- Müəyyən şəbəkələr arasında yalnız HTTP/HTTPS trafikinə icazə vermək
- Qonaq şəbəkəsini daxili resurslardan izolyasiya etmək

Dashboard-da **Firewall** səhifəsindən daxil olun.

---

## 📸 Ekran Görüntüləri (Screenshots)

### Web Dashboard (İdarə Paneli)
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/web/0.png" alt="Web 0" width="45%">
  <img src="web/public/photo/web/1.png" alt="Web 1" width="45%">
  <img src="web/public/photo/web/2.png" alt="Web 2" width="45%">
  <img src="web/public/photo/web/3.png" alt="Web 3" width="45%">
  <img src="web/public/photo/web/4.png" alt="Web 4" width="45%">
  <img src="web/public/photo/web/5.png" alt="Web 5" width="45%">
  <img src="web/public/photo/web/6.png" alt="Web 6" width="45%">
  <img src="web/public/photo/web/7.png" alt="Web 7" width="45%">
  <img src="web/public/photo/web/8.png" alt="Web 8" width="45%">
  <img src="web/public/photo/web/9.png" alt="Web 9" width="45%">
  <img src="web/public/photo/web/10.png" alt="Web 10" width="45%">
  <img src="web/public/photo/web/11.png" alt="Web 11" width="45%">
  <img src="web/public/photo/web/12.png" alt="Web 12" width="45%">
</div>

### Installer (Quraşdırıcı)
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/installer/0.png" alt="Installer 0" width="45%">
  <img src="web/public/photo/installer/1.png" alt="Installer 1" width="45%">
  <img src="web/public/photo/installer/2.png" alt="Installer 2" width="45%">
  <img src="web/public/photo/installer/3.png" alt="Installer 3" width="45%">
  <img src="web/public/photo/installer/4.png" alt="Installer 4" width="45%">
</div>

---

## 🤝 Töhfə Vermək (Contributing)

Töhfələrinizi gözləyirik ❤️
Xəta hesabatları (Bug reports), yeni funksiya təklifləri və Pull Request-lər yüksək qiymətləndirilir.

Töhfə verməzdən əvvəl zəhmət olmasa **Developer Təlimatlarını** oxuyun.

---

## ⭐ Layihəyə Dəstək

Əgər **NovusGate** sizin üçün faydalıdırsa:

* ⭐ Repozitoriyaya ulduz (Star) verin
* 🐛 Xətalar barədə məlumat verin (Issues)
* 💡 Yeni ideyalar təklif edin
* 📣 Başqaları ilə paylaşın

Açıq-qaynaq (Open-source) icma ilə yaşayır.

---

## 🤝 Professional Dəstək / Enterprise Support

> **Quraşdırma çətin gəlir?** Biz sizə kömək edə bilərik!

Əgər bu təlimatda göstərilən addımları özünüz icra edə bilmirsinizsə və ya enterprise səviyyəsində tam dəstək lazımdırsa, bizə müraciət edə bilərsiniz:

### Ödənişli Xidmətlər

| Xidmət | Təsvir |
|--------|--------|
| 🛠️ **Tam Quraşdırma** | NovusGate-in sizin infrastrukturda tam quraşdırılması |
| 🔧 **Server Konfiqurasiyası** | Linux, Docker, Firewall və Təhlükəsizlik konfiqurasiyası |
| 📞 **Texniki Dəstək** | Problem həlli və davamlı dəstək |
| 📚 **Təlim** | Komandanız üçün NovusGate istifadəsi təlimi |

> 💰 **Qiymətləndirmə**: Xidmət haqqı görüləcək işin həcminə və mürəkkəbliyinə əsasən fərdi olaraq hesablanır. Pulsuz konsultasiya üçün bizimlə əlaqə saxlayın.

### Əlaqə

📧 **Email**: Ali.Z.Zeynalli@gmail.com  
💼 **LinkedIn**: [linkedin.com/in/ali7zeynalli](https://linkedin.com/in/ali7zeynalli)  
📱 **Telefon**: +49 152 2209 4631 (whatsapp)

> 💼 Enterprise müştərilər üçün SLA (Service Level Agreement) ilə dəstək mövcuddur.

### 🌍 Dəstək Verilən Dillər

| Dil | Language |
|-----|----------|
| 🇦🇿 Azərbaycan | Azerbaijani |
| 🇬🇧 İngilis | English |
| 🇩🇪 Alman | German |
| 🇷🇺 Rus | Russian |
| 🇹🇷 Türk | Turkish |

---

## 📄 Lisenziya

Bu layihə **Apache License 2.0** altında lisenziyalanıb - ətraflı məlumat üçün [LICENSE](LICENSE) faylına baxın.

**© 2025 Əli Zeynallı**

Apache 2.0 Lisenziyası sizə imkan verir:
- ✅ Proqramı istənilən məqsəd üçün istifadə etmək (kommersiya daxil)
- ✅ Proqramı dəyişdirmək və paylamaq
- ✅ Töhfə edənlərin patent iddialarından istifadə etmək

Sizdən tələb olunur:
- 📋 Orijinal müəllif hüququ qeydini saxlamaq
- 📋 LICENSE və NOTICE fayllarını daxil etmək
- 📋 Proqrama edilən əhəmiyyətli dəyişiklikləri qeyd etmək
- 📋 Orijinal müəllifə istinad vermək

> 📜 Attribution tələbləri üçün [NOTICE](NOTICE) faylına baxın.

---

**[Ali Zeynalli](https://github.com/Ali7Zeynalli) tərəfindən hazırlanıb**  
*Project NovusGate*

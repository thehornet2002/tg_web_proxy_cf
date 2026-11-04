# Telegram Web Proxy on Cloudflare Workers

پروکسی وب تلگرام بر پایه‌ی **Cloudflare Workers** و `cloudflare:sockets` است. این پروژه بدون سرور اختصاصی، اتصال WebSocket را به دیتاسنترهای تلگرام منتقل می‌کند و برای استقرار روی یک دامنه‌ی متصل به Cloudflare طراحی شده است.

> **هشدار امنیتی:** مقدار `PROXY_SECRET` و لینک‌های تولیدشده توسط داشبورد را محرمانه نگه دارید. هر شخصی که به لینک یا secret دسترسی داشته باشد می‌تواند از سهمیه‌ی Worker شما استفاده کند.

## قابلیت‌ها

- Relay چندکاناله‌ی WebSocket برای اتصال Telegram Web Proxy
- پشتیبانی از دیتاسنترهای تلگرام ۱ تا ۵
- رمزنگاری handshake و داده‌ها با Obfuscated2 و AES-CTR
- توکن‌های stateless با HMAC-SHA-256 و امکان لغو توکن session
- محدودسازی تعداد sessionها در هر isolate و برای هر IP
- تشخیص اتصال‌های idle و پاک‌سازی منابع socket
- صفحه‌ی مدیریتی محافظت‌شده برای ساخت لینک `tg://webproxy`
- قابلیت camouflage با `CAMOUFLAGE_URL`
- پاسخ‌های امن برای مسیرهای ناشناخته و جلوگیری از cache شدن sessionها

## پیش‌نیازها

- حساب Cloudflare با دسترسی Workers
- یک دامنه که روی Cloudflare فعال باشد
- Node.js و Wrangler برای استقرار محلی

نصب Wrangler:

```bash
npm install -g wrangler
wrangler login
```

## استقرار

مخزن را دریافت کنید و به پوشه‌ی پروژه بروید:

```bash
git clone https://github.com/thehornet2002/tg_web_proxy_cf.git
cd tg_web_proxy_cf
```

یک secret امن ۳۲ بایتی تولید کنید:

```bash
openssl rand -hex 16
```

Secretها را در Cloudflare ذخیره کنید:

```bash
wrangler secret put PROXY_SECRET
wrangler secret put ADMIN_TOKEN
```

مقدار `PROXY_SECRET` باید دقیقاً ۳۲ رقم hex باشد؛ پیشوند اختیاری `dd` نیز پشتیبانی می‌شود. مقدار `ADMIN_TOKEN` باید حداقل ۲۰ کاراکتر داشته باشد.

سپس Worker را deploy کنید:

```bash
wrangler deploy
```

در داشبورد Cloudflare، یک route یا custom domain برای Worker تنظیم کنید. پس از آن آدرس Worker شما مانند زیر خواهد بود:

```text
https://proxy.example.com
```

## ساخت لینک اتصال تلگرام

برای نمایش داشبورد مدیریت، مقدار `ADMIN_TOKEN` را به‌صورت query string ارسال کنید:

```text
https://proxy.example.com/?admin=YOUR_ADMIN_TOKEN
```

داشبورد لینک‌های زیر را تولید می‌کند:

- لینک مستقیم تلگرام: `tg://webproxy?...`
- لینک وب تلگرام: `https://t.me/webproxy?...`

این URLها حاوی secret پروکسی هستند و نباید عمومی یا در issue، log و analytics منتشر شوند.

## متغیرهای محیطی

| نام | وضعیت | توضیح |
|---|---|---|
| `PROXY_SECRET` | ضروری | secret اصلی؛ ۳۲ رقم hex، با امکان پیشوند `dd` |
| `ADMIN_TOKEN` | اختیاری | فعال‌سازی داشبورد؛ حداقل ۲۰ کاراکتر |
| `TOKEN_SALT` | اختیاری | با تغییر آن، تمام توکن‌های صادرشده نامعتبر می‌شوند |
| `CAMOUFLAGE_URL` | اختیاری | آدرس HTTPS سایت نمایشی برای درخواست‌های ناشناس |
| `MAX_DIALS` | اختیاری | سقف تلاش‌های اتصال به دیتاسنتر؛ مقدار پیش‌فرض ۴۵ |
| `MAX_SESSIONS` | اختیاری | سقف session در هر isolate؛ مقدار پیش‌فرض ۳۰۰ |
| `MAX_SESSIONS_PER_IP` | اختیاری | سقف session برای هر IP؛ مقدار پیش‌فرض ۲۴ |

برای تنظیم مقدارهای غیرحساس می‌توانید از داشبورد Cloudflare یا بخش `[vars]` در `wrangler.toml` استفاده کنید. secretها را داخل فایل‌های version control قرار ندهید.

نمونه‌ی تنظیمات اختیاری:

```toml
[vars]
CAMOUFLAGE_URL = "https://www.example.com"
MAX_DIALS = "45"
MAX_SESSIONS = "300"
MAX_SESSIONS_PER_IP = "24"
```

## مسیرهای داخلی

این مسیرها توسط کلاینت تلگرام و bridge داخلی استفاده می‌شوند:

- `GET /?bridge=<capability>`: دریافت bridge HTML کوتاه‌عمر
- `GET /?admin=<token>`: داشبورد مدیریت
- `POST /api/v1/session`: ایجاد session
- `DELETE /api/v1/session`: لغو session
- `GET /api/v1/ws`: اتصال WebSocket چندکاناله

درخواست‌های دیگر به `CAMOUFLAGE_URL` هدایت می‌شوند؛ اگر camouflage تنظیم نشده باشد، پاسخ 404 دریافت می‌کنند.

## تست و توسعه

اجرای محلی:

```bash
wrangler dev
```

برای تست محلی، secretها را در فایل `.dev.vars` قرار دهید. این فایل را commit نکنید:

```dotenv
PROXY_SECRET=0123456789abcdef0123456789abcdef
ADMIN_TOKEN=replace-with-a-long-random-admin-token
CAMOUFLAGE_URL=https://www.example.com
```

بررسی نحوی فایل Worker:

```bash
node --check worker.js
```

## نکات عملیاتی و امنیتی

1. از secret پیش‌فرض یا قابل حدس استفاده نکنید؛ Worker در صورت مشاهده‌ی مقدار پیش‌فرض، proxy را غیرفعال می‌کند.
2. `ADMIN_TOKEN` را در URL عمومی، history مرورگر یا logهای قابل دسترس ذخیره نکنید.
3. برای بی‌اعتبار کردن همه‌ی sessionهای قبلی، `TOKEN_SALT` را تغییر دهید و secret را دوباره deploy کنید.
4. `CAMOUFLAGE_URL` باید HTTPS باشد و بهتر است سایتی باشد که اجازه‌ی proxy شدن محتوایش را دارید.
5. محدودیت‌های session را متناسب با سهمیه‌ی Cloudflare و ترافیک واقعی تنظیم کنید.
6. این پروژه یک relay است؛ قوانین تلگرام، Cloudflare و قوانین محل استفاده‌ی خود را رعایت کنید.

## ساختار پروژه

```text
.
├── worker.js       # منطق کامل Cloudflare Worker
├── wrangler.toml   # تنظیمات استقرار Wrangler
├── README.md       # راهنمای نصب، تنظیم و استفاده
└── LICENSE         # مجوز MIT
```

## مجوز

این پروژه تحت مجوز [MIT](./LICENSE) منتشر شده است.

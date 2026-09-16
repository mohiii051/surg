# Surge Admin Panel 19.4.1 — Control Center Upgrade

این نسخه پنل ادمین را به یک مرکز مدیریت یکپارچه برای عملیات روزمره Surge تبدیل می‌کند.

## مدیریت کاربران
- جست‌وجوی Email و User ID
- فعال/غیرفعال‌سازی حساب
- کپی User ID
- تعداد Device و License در همان Grid

## مدیریت دستگاه‌ها
- جست‌وجوی Device ID، نام دستگاه، HWID و Email
- Block / Unblock
- Release HWID
- کپی HWID و Device ID

## مدیریت لایسنس
- جست‌وجو
- مشاهده وضعیت Lock / Banned / HWID
- Create
- Copy Key برای کلیدهای ایجادشده در همین Session
- Rotate Key برای کلیدهای قدیمی که فقط Hash آنها روی سرور باقی مانده است
- Revoke / Restore
- Expire
- Extend با تعداد روز دلخواه
- Release Device

## امنیت کلید
سرور کلیدهای قدیمی را به‌صورت plaintext ذخیره نمی‌کند. بنابراین «نمایش کلید قدیمی» از روی Hash ممکن نیست. برای یک License قدیمی، عملیات Rotate Key یک کلید جدید تولید و کلید قبلی را بی‌اعتبار می‌کند.

## لاگ و Backup
- فیلتر محلی Audit Log
- Copy رویداد انتخاب‌شده
- Backup / Refresh / Restore

## Server Control
Health و Control Availability از هم جدا هستند. در دسترس نبودن Control نباید Server Health را اشتباهاً قرمز کند.

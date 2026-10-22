<div align="center" dir="rtl">

<img src="assets/hero_banner.png" alt="R3X-BugBounty — منظومة أمن سيبراني ذكية ومتعددة الوكلاء" width="800"/>

# R3X-BugBounty — منظومة أمن سيبراني ذكية ومتعددة الوكلاء [v2.0.0]
### منصة تقييم أمني وفحص ثغرات آلية مصرح بها تعمل عبر الطرفية (CLI)

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Release-v2.0.0--Evolution-green.svg)](https://github.com/r3xdec-bit/r3x-bugbounty)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Bandit%20Passing-brightgreen.svg)](https://github.com/r3xdec-bit/r3x-bugbounty)
[![Multi-Agent](https://img.shields.io/badge/Agents-12%20Autonomous%20%2B%20Debate-purple.svg)](https://github.com/r3xdec-bit/r3x-bugbounty)
[![Evidence-First](https://img.shields.io/badge/Evidence-SHA--256%20Verified-cyan.svg)](https://github.com/r3xdec-bit/r3x-bugbounty)

[English](../README.md) • [العربية](README_AR.md) • [المعمارية التقنية](ARCHITECTURE.md) • [دليل التثبيت](INSTALLATION.md) • [سجل التغييرات](CHANGELOG.md)

</div>

---

## 🎯 نظرة عامة

**R3X-BugBounty** هو إطار عمل مفتوح المصدر مصمم خصيصاً لعمليات تدقيق أمن تطبيقات الويب وتقييم الثغرات المصرح بها وبرامج مكافآت الثغرات (Bug Bounty). يعمل النظام بالكامل داخل الطرفية (Terminal Only) ويتم توجيهه بواسطة **12 وكيلاً ذكياً مستقلاً ومحركات استنتاج معرفية متقدمة**، مع رقابة صارمة على النطاق المصرح به بواسطة **Scope Guardian**، ومحكمة مناظرة ثلاثية بين الوكلاء لمنع النتائج الإيجابية الخاطئة تماماً (Zero False Positives).

---

## ⚡ أبرز الخصائص (إصدار V2 Evolution)

- **واجهة طرفية تفاعلية ولوحة تحكم حية (Live Dashboard)**: متابعة حية لجميع الوكلاء والمهام وتكاليف واجهات الذكاء الاصطناعي في شاشة واحدة (`r3x dashboard`).
- **إدارة ديناميكية للأدوات بموافقة مسبقة (Consent-First Tool Manager)**: فحص مسارات PATH للأدوات الأمنية تلقائياً، وتثبيت الأدوات في `~/.local/bin`، وتحميل الأدوات الخارجية **فقط بعد موافقة صريحة من المستخدم**.
- **فاحص الصلاحيات المقارن (Authenticated Differential Scanner)**: مقارنة وصول الجلسات (بدون مصادقة / مستخدم عادي / مستخدم ذو صلاحية) لكشف ثغرات BOLA/IDOR و BFLA بدقة تجريبية.
- **العقل العصبي (R3X Neural Brain)**: محرك استنتاجي يربط الثغرات البسيطة المتفرقة في سلاسل هجومية مركبة وعالية الخطورة (Chained Attack Vectors).
- **محكمة المناظرة الثلاثية (3-Agent Adversarial Debate)**: مناظرة جدلية صارمة بين (المدعي العام - محامي الدفاع - رئيس القضاة) للتحقق القاطع من صحة كل ثغرة.
- **مخطط سطح الهجوم الذكي (Attack Surface Graph)**: بناء شجرة طوبولوجية مرئية للهدف في الطرفية بالاعتماد على NetworkX (`r3x surface`).
- **AI Mixer V2 وحارس الميزانية (Budget Guard)**: إدارة متقدمة للمفاتيح مع قفل مالي صارم يمنع تجاوز الميزانية المحددة للمشروع ومحرك لتقييم النماذج بناءً على السرعة والتكلفة والجودة.
- **إشعارات Webhook متعددة القنوات**: إرسال التنبيهات الفورية إلى Slack و Discord و Telegram مع تعتيم فوري وتلقائي لأي مفاتيح أو بيانات اعتماد حساسة.
- **توافق شامل مع توزيعات لينكس و WSL**: دعم كامل لـ Kali Linux و Arch Linux و Ubuntu و Debian و Fedora/RHEL و openSUSE بالإضافة إلى بيئة WSL 1 & 2.
- **إطار التعافي والمعالجة الذاتية (Self-Healing Framework)**: تشخيص ذاتي للأعطال وانقطاعات الاتصال وحدود الـ Rate Limits وإعادة المحاولة الآمنة.
- **محسّن الفحص الذكي (Scan Optimizer)**: فحص أولي لطبيعة الهدف يتخطى الفحوصات غير الضرورية ويسرّع العملية بنسبة 60%.
- **مدقق الأدلة الذكي (AI Evidence Validator)**: التحقق من التشفير ببصمات SHA-256 وضمان عدم تسريب أي أسرار أو كلمات مرور في التقارير.
- **متجر الإضافات والامتدادات (Plugin Marketplace)**: إمكانية تفعيل وتثبيت أدوات فحص مخصصة في بيئة معزولة الصلاحيات (`r3x plugin`).
- **مولد تقارير منصات الثغرات الجاهزة (Bug Bounty Submissions)**: تصدير تقارير مهيأة للرفع الفوري على HackerOne و Bugcrowd بنقرة واحدة (`r3x report --bounty`).
- **تكامل وكيل Hermes و HexStrike AI MCP v6.0**: ربط مستقل ومعياري مع النماذج الرسمية وتوليد مسارات استكشاف تلقائية.

---

## 🤖 منظومة الوكلاء الـ 12

| # | اسم الوكيل | الدور والمسؤولية |
|---|---|---|
| 1 | **HermesMasterOrchestrator** | الوكيل القائد: التخطيط، توزيع المهام، إدارة السياق والذاكرة |
| 2 | **ScopeGuardianAgent** | حارس النطاق: التحقق من النطاق المصرح به، ومنع التجاوزات |
| 3 | **ReconAgent** | الاستطلاع السلبي، فحص سجلات DNS، وبصمة التقنيات |
| 4 | **WebSecurityAgent** | فحص ترويسات الأمان HTTP، وسياسات CORS، وملفات الكوكيز، وتشفير TLS |
| 5 | **APISecurityAgent** | اكتشاف وتدقيق واجهات برمجة التطبيقات ومخططات OpenAPI/Swagger |
| 6 | **JSAnalysisAgent** | التحليل الاستاتيكي لملفات JavaScript واستخراج المسارات والمفاتيح المسربة |
| 7 | **AuthDifferentialAgent** | فحص الصلاحيات المقارن واكتشاف ثغرات BOLA/IDOR و BFLA بين الأدوار المختلفة |
| 8 | **CVEIntelligenceAgent** | ربط الإصدارات البرمجية المكتشفة بقواعد بيانات الثغرات المعروفة |
| 9 | **FalsePositiveVerificationAgent** | محكمة المناظرة والتحقق التوافقي لمنع النتائج الإيجابية الزائفة |
| 10 | **EvidenceCollectorAgent** | تنقية الأدلة، وتوليد بصمة SHA-256، وإرسال الـ Webhooks، والحفظ الدائم |
| 11 | **AIMixerAgent** | إدارة استهلاك الرموز، وتبديل المزودين، وحارس الميزانية المالي |
| 12 | **ReportGeneratorAgent** | تجميع وتوليد التقارير النهائية وتصدير تقارير منصات مكافآت الثغرات |

---

## 🚀 التثبيت السريع

يعمل سكربت التثبيت التلقائي على توزيعات **Kali Linux**, **Arch Linux**, **Ubuntu**, **Debian**, **Fedora/RHEL**, **openSUSE**, و **WSL**:

```bash
git clone https://github.com/r3xdec-bit/r3x-bugbounty.git
cd r3x-bugbounty
chmod +x install.sh
./install.sh
```

لتشغيل الواجهة التفاعلية:
```bash
source .venv/bin/activate
r3x
```

---

## 🛠️ أهم الأوامر

```bash
# لوحة التحكم الحية وفحص جاهزية النظام
r3x dashboard
r3x doctor

# إدارة المشاريع والأهداف
r3x project new my-target
r3x target add https://target.example.com --project my-target
r3x scope import scope.json --project my-target

# إدارة مفاتيح AI Mixer وحارس الميزانية
r3x mixer add nvidia
r3x mixer add openrouter
r3x mixer add ollama
r3x mixer list
r3x mixer status

# تشغيل الفحوصات الأمنية المصرح بها
r3x scan --quick --project my-target
r3x scan --full --project my-target
r3x scan --api --project my-target

# عرض شجرة طوبولوجيا سطح الهجوم
r3x surface --project my-target

# متجر الإضافات والامتدادات
r3x plugin list
r3x plugin enable waf_fingerprint

# استعراض النتائج والأدلة المشفرة
r3x findings --project my-target
r3x evidence
r3x history
r3x resume

# إنشاء وتصدير التقارير وتقارير مكافآت الثغرات الجاهزة
r3x report --bounty --project my-target
r3x report --html --project my-target
r3x report --md --project my-target
r3x report --json --project my-target
```

---

## 📄 الترخيص

هذا المشروع مرخص تحت رخصة **MIT**. راجع ملف [LICENSE](LICENSE) لمزيد من التفاصيل.

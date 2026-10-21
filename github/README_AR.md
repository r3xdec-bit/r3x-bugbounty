<div align="center" dir="rtl">

<img src="../assets/logo.png" alt="شعار R3X-BugBounty" width="260"/>

# R3X-BugBounty — منظومة أمن سيبراني ذكية ومتعددة الوكلاء
### منصة تقييم أمني وفحص ثغرات آلية مصرح بها تعمل عبر الطرفية (CLI)

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Audit%20%26%20Recon-red.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Multi-Agent](https://img.shields.io/badge/Agents-11%20Autonomous-purple.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Evidence-First](https://img.shields.io/badge/Evidence-SHA--256%20Verified-cyan.svg)](https://github.com/r3xdec/r3x-bugbounty)

[English](README.md) • [العربية](README_AR.md) • [المعمارية التقنية](ARCHITECTURE.md) • [دليل التثبيت](INSTALLATION.md) • [سجل التغييرات](CHANGELOG.md)

</div>

---

## 🎯 نظرة عامة

**R3X-BugBounty** هو إطار عمل مفتوح المصدر مصمم خصيصاً لعمليات تدقيق أمن تطبيقات الويب وتقييم الثغرات المصرح بها وبرامج مكافآت الثغرات (Bug Bounty). يعمل النظام بالكامل داخل الطرفية (Terminal Only) ويتم توجيهه بواسطة **11 وكيلاً ذكياً مستقلاً**، مع رقابة صارمة على النطاق المصرح به بواسطة **Scope Guardian**، ومحرك تحقق قائم على مقارنة إجابات نموذجين مستقلين لمنع النتائج الإيجابية الخاطئة (False Positives).

---

## ⚡ أبرز الخصائص

- **واجهة طرفية تفاعلية (Interactive REPL)**: توفر الإكمال التلقائي بالأزرار (Tab Completion)، وعرضاً حياً لحالة الاتصالات، وتنسيقات Rich المتقدمة.
- **R3X AI Mixer**: إضافة عدة مفاتيح API لكل مزود (**NVIDIA NIM**, **OpenRouter**, **OpenAI**, **Gemini**, **Ollama المحلي**). موازنة الأحمال، والتبديل التلقائي (Fallback)، وتتبع التكاليف واستهلاك الرموز (Tokens).
- **محرك التحقق الثنائي (Dual-Model Verifier)**: مقارنة تحليل نموذجين ذكاء اصطناعي مستقلين قبل اعتماد أي نتيجة أمنية عالية الخطورة.
- **تكامل وكيل Hermes**: تواصل مستقل ومتوافق مع [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) لتخطيط الفحوصات والاحتفاظ بسياق العمليات السابقة.
- **تكامل HexStrike AI MCP v6.0**: اكتشاف ديناميكي لأدوات بروتوكول MCP وقراءة هياكل البيانات (Schemas) المتوافقة مع [HexStrike AI MCP](https://github.com/0x4m4/hexstrike-ai).
- **حارس النطاق (Scope Guardian Agent)**: فرض صارم للنطاقات المصرح بها، واستثناءات الروابط، ومنع مصائد إعادة التوجيه (Redirect Traps)، وتحديد معدل الطلبات (Rate Limiting).
- **محرك الأدلة المشفرة (Evidence-First Engine)**: حجب تلقائي لكافة البيانات الحساسة (Bearer Tokens, Cookies, Passwords) وتوليد بصمات SHA-256 فريدة للأدلة.
- **تقارير احترافية**: توليد تقارير جاهزة للتقديم على منصات مكافآت الثغرات بصيغ **HTML**, **Markdown**, **JSON**, **PDF**.

---

## 🤖 منظومة الوكلاء الـ 11

| # | اسم الوكيل | الدور والمسؤولية |
|---|---|---|
| 1 | **HermesMasterOrchestrator** | الوكيل القائد: التخطيط، توزيع المهام، إدارة السياق والذاكرة |
| 2 | **ScopeGuardianAgent** | حارس النطاق: التحقق من النطاق المصرح به، ومنع التجاوزات |
| 3 | **ReconAgent** | الاستطلاع السلبي، فحص سجلات DNS، وبصمة التقنيات |
| 4 | **WebSecurityAgent** | فحص ترويسات الأمان HTTP، وسياسات CORS، وملفات الكوكيز، وتشفير TLS |
| 5 | **APISecurityAgent** | اكتشاف وتدقيق واجهات برمجة التطبيقات ومخططات OpenAPI/Swagger |
| 6 | **JSAnalysisAgent** | التحليل الاستاتيكي لملفات JavaScript واستخراج المسارات والمفاتيح المسربة |
| 7 | **CVEIntelligenceAgent** | ربط الإصدارات البرمجية المكتشفة بقواعد بيانات الثغرات المعروفة |
| 8 | **FalsePositiveVerificationAgent** | التحقق التوافقي بين نموذجين لمنع النتائج الإيجابية الزائفة |
| 9 | **EvidenceCollectorAgent** | تنقية الأدلة، وتوليد بصمة SHA-256، والحفظ في الذاكرة الدائمة SQLite |
| 10 | **AIMixerAgent** | إدارة استهلاك الرموز، وتبديل المزودين، ومراقبة التكاليف |
| 11 | **ReportGeneratorAgent** | تجميع وتوليد التقارير النهائية بمختلف الصيغ |

---

## 🚀 التثبيت السريع

يعمل سكربت التثبيت التلقائي على توزيعات **Kali Linux**, **Arch Linux**, **Ubuntu**, **Debian**:

```bash
git clone https://github.com/r3xdec/r3x-bugbounty.git
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
# فحص جاهزية النظام والأدوات
r3x doctor

# إدارة المشاريع والأهداف
r3x project new my-target
r3x target add https://target.example.com --project my-target
r3x scope import scope.json --project my-target

# إدارة مفاتيح AI Mixer
r3x mixer add nvidia
r3x mixer add openrouter
r3x mixer add ollama
r3x mixer list
r3x mixer status

# تشغيل الفحوصات الأمنية المصرح بها
r3x scan --quick --project my-target
r3x scan --full --project my-target
r3x scan --api --project my-target

# استشارة عقل الذكاء الاصطناعي (AI Pentest Brain)
r3x ai --target https://target.example.com

# استعراض النتائج والأدلة
r3x findings --project my-target
r3x evidence
r3x history
r3x resume
r3x diff scan_id_1 scan_id_2

# إنشاء التقارير
r3x report --html --project my-target
r3x report --md --project my-target
r3x report --json --project my-target
```

---

## 📄 الترخيص

هذا المشروع مرخص تحت رخصة **MIT**. راجع ملف [LICENSE](LICENSE) لمزيد من التفاصيل.

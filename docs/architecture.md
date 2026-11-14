# hveritas — Verified Autonomous Goal Loop

**Tek cümle:** Doğal dilde bir hedef ver; sistem onu *kontrol edilebilir* bir spec'e derler,
izole bir ortamda çalıştırır, her eylemin etkisini **bağımsız ölçer**, katmanlı bir verifier'dan
geçirir, hata olursa yerini **deterministik replay bisect** ile bulur (LLM yargısıyla değil),
bütçeli onarım yapar ve kaçan her hatadan kendi verifier'ını güçlendirir.

**Tasarımın tek dayanağı:** doğrulama artık üretmekten daha zor (*The Verification Horizon*,
arXiv 2606.26300) ve LLM kendi doğrulayıcısı olamıyor (Stechly et al., arXiv 2402.08115;
Huang et al., arXiv 2310.01798 — intrinsic self-correction Llama-2 GSM8K'da %62.0 → %36.5).
Bu yüzden mimarinin merkezinde "ajan kendini eleştirir" döngüsü **yok**.

---

## 0. Pazarlığa kapalı invariant'lar

Bunlardan biri ihlal edilirse sistem ölçüm yapmıyor, tiyatro yapıyor.

| # | Invariant | Neden (kanıt) |
|---|---|---|
| I1 | Verifier, generator ile aynı process / yazılabilir dosya yolu / model çağrısını **asla** paylaşmaz | Stechly: sağlam dış verifier kazandırır, self-verify çökertir |
| I2 | Hata yeri **replay bisect** ile bulunur; LLM yalnızca verilen yeri *anlatır*, asla üretmez | *Credit Without Ground Truth* (2608.19760): LLM-judge, logprob oranı ve policy'nin kendi counterfactual'ı — hiçbiri executed-replay gerçeğiyle örtüşmedi |
| I3 | Ledger'daki her etki bir **probe** ile ölçülür, ajanın kendi raporundan asla alınmaz | *Building to the Test* (2606.28430): ajan istenen şeyi değil ölçülen şeyi teslim ediyor |
| I4 | İki oracle: **in-loop proxy** (ajan koşturabilir) + **held-out** (ajan asla okuyamaz). Held-out dosyaları worker dosya sisteminde hiç var olmaz | ImpossibleBench: testleri gizlemek hile oranını ~0'a indirdi |
| I5 | Her milestone doğrulaması önce **no-op baseline** koşar. Hiçbir şey yapmayan ajan ε'dan fazla puan alırsa koşu *harness hatası* olarak iptal edilir — ajan sonucu olarak değil | *Building to the Test*'in kontrol yöntemi |
| I6 | Ajanın workspace'indeki hiçbir şey verifier'ı etkileyemez: `conftest.py`, `sitecustomize.py`, `PYTHONPATH`, `PATH`, shim binary yok. Verifier `python -I` ve pinlenmiş read-only toolchain imajı kullanır | BenchJack: SWE-bench Verified'da kök `conftest.py` pytest hook'u ile **%100**; Terminal-Bench'te `/usr/bin/curl` trojanı ile **%100** |
| I7 | Grader ajan çıktısını **asla** `eval`/`exec` etmez. LLM judge'a giden her girdi sanitize edilir | BenchJack: OSWorld grader'ında `eval()` → %73; CAR-bench'te gizli HTML judge'ı yanıltıyor → %100 |
| I8 | Her koşu replay edilebilir: pinlenmiş container digest, seed'li sampling, kayıtlı tool yanıtları, FS snapshot | TraceElephant (2604.22708): tam trace atfı **%76'ya kadar** iyileştiriyor |
| I9 | Verifier sabit değil: kaçan her hata yeni bir invariant/ilişki/test doğurur; mutation score düşemez | *Verification Horizon*: sabit hiçbir ödül fonksiyonu yetenek büyüdükçe geçerli kalmıyor |

---

## 1. Döngü

```
GOAL (doğal dil)
  │
  ▼
[1] SPEC COMPILER ───────────────────────────────────────────────────
     goal → requirement DAG (ikili, kontrol edilebilir düğümler)
     her düğüme: proxy kontrol + held-out kabul kriteri
     belirsizlik kapısı: çözümsüz/çelişkili spec → İNSANA sor, tahmin etme
  │
  ▼
[2] SPEC AUDIT GATE ─────────────────────────────────────────────────
     no-op baseline spec üzerinde 0 almalı   (almıyorsa spec bozuk)
     imkânsızlık taraması: proxy ile held-out çelişiyor mu?
     leakage taraması: cevap workspace'te veya ağda duruyor mu?
  │
  ▼
[3] TASK GRAPH ──────────────────────────────────────────────────────
     DAG → yaprak task'lar; her task'a verifier sözleşmesi + bütçe
  │
  ▼
[4] EXECUTE  (worker ajan, sandbox içinde, held-out'u göremez)
     ├── Action Envelope : pre-state hash · tool · args · maliyet
     ├── Effect Receipt  : post-state BAĞIMSIZ ölçüm (I3)
     │                     fs diff · exit code · db delta · http yan etki
     │                     · screenshot + AX-tree hash
     └── Tool Tape       : kayıtlı tool yanıtları + env snapshot → replay handle
  │
  ▼
[5] VERIFIER BUS  (ayrı container, ağ kapalı, repo read-only mount)
     T0 deterministik : derleyici · type checker · schema · lint · in-loop proxy test
     T1 invariant     : axe-core · perf bütçesi · API sözleşmesi · güvenlik taraması
     T2 metamorphic   : oracle gerektirmeyen ilişki süiti (2406.06864: %75 yakalama, %8.6 FP)
     T3 held-out      : gizli kabul oracle'ı — milestone başına BİR kez, ajan asla görmez
     T4 judge         : requirement-DAG agent-as-judge, EN SON, asla tek başına,
                        her verdict kanıtla (2410.10934: %90 vs LLM-judge %70)
  │
  ▼
[6] DECIDE
     ┌─ hepsi geçti ──────────────────► milestone commit
     ├─ T0–T2 düştü ─────────────────► [7] ATTRIBUTE → [8] REPAIR
     └─ T0–T2 geçti ama T3 DÜŞTÜ ────► ⚠ GAMING ALARM → sert durdur + insan
  │
  ▼
[7] ATTRIBUTE  (yalnız hata halinde, bütçeli)
     a. DARALT   : tool tape üzerinde ikili arama + replay — LLM YOK, O(log n) replay
     b. DOĞRULA  : şüpheli adımda counterfactual replay, N=5..10, Monte-Carlo CI
     c. SINIFLA  : TRAIL taksonomisi (3 grup → 9 kategori → 20 yaprak tip)
     d. ANLAT    : LLM insan hikâyesini yazar — EN SON, ve bulunan yeri DEĞİŞTİREMEZ
  │
  ▼
[8] REPAIR  (sınırlı)
     attributed cause enjekte edilerek ≤ K deneme
     merdiven: aynı model → daha sıkı kısıt/daha küçük adım → FARKLI model ailesi → insan
     ilerleme yok dedektörü: aynı atıf iki kez → merdiveni atla, yukarı çık
  │
  ▼
[9] EVOLVE
     kaçan her hata → yeni invariant / metamorphic ilişki / regresyon testi
     verifier süitinin mutation score'u düşemez (I9 kapısı)
     kendi harness'ına zamanlanmış BenchJack taraması
  │
  ▼
LEDGER (append-only, OTel GenAI semconv) → her koşu yeniden oynatılabilir
```

---

## 2. Gaming alarmı — bu mimarinin asıl buluşu

İki oracle tut ve farkı ölç:

```
Δ = score_proxy − score_heldout        (milestone başına)
```

- **Δ ≈ 0** → dürüst iş.
- **Δ büyük** → *building to the test*. Ajan görünen kontrolü tatmin ediyor, istenen işi yapmıyor.

Bu, hileyi **otomatik ve sayısal** olarak yakalayan tek sinyal. *Building to the Test* deneyinde
tam bu desen görülüyor: oracle döngüye girince puan neredeyse tam, ama kütüphane ölü, davranış
test edilen demo'nun içine gömülmüş. Δ eşiği aşıldığında döngü devam etmez — insana çıkar.

İkinci güvenlik ağı: **no-op baseline** her milestone'da koşar (I5). Ucuz, ve harness
hatalarının çoğunu ajan başarısı sanmanı engeller.

---

## 3. Scorer izolasyonu — somut gereksinimler

BenchJack'in 8 benchmark'ta bulduğu exploit'lerin **hepsi** bu listeyle kapanıyor:

1. Verifier **ayrı container**, `--network=none`, non-root, dropped capabilities.
2. Repo verifier'a **read-only** mount edilir.
3. Verifier kodu ajanın ağacında **hiç bulunmaz** (ayrı yol: `~/.local/share/hveritas/verifier/`).
4. Held-out oracle'lar **ayrı repo**, şifreli, yalnız verifier container'ına mount edilir.
5. Python her zaman `-I` ile (izole mod: workspace'ten import yok, `PYTHONPATH` yok).
6. Test toplama kökü workspace değil; `conftest.py` / `sitecustomize.py` / plugin auto-load **kapalı**.
7. Toolchain pinlenmiş imajdan, `PATH` sabit → binary trojanı imkânsız.
8. Grader ajan çıktısını parse eder, **asla** `eval`/`exec` etmez.
9. Judge girdisi sanitize edilir: HTML/yorum/zero-width karakter temizliği, talimat-benzeri blokların çıkarılması.
10. Ağ: worker'da allow-list; held-out'u barındıran hiçbir host erişilebilir değil.

---

## 4. Determinizm ve replay bütçesi

Replay olmadan atıf tahmindir (I2). Gerekli olanlar:

- Container image **digest** ile pinlenir (tag değil).
- Model çağrıları seed'li; sağlayıcı yanıtları **tape**'e kaydedilir (vcrpy tarzı).
- Saat, env, locale, rastgele kaynaklar dondurulur.
- FS snapshot: Btrfs snapshot (bu makinede `hrollback` zaten var) veya overlayfs.

LLM sampling tam deterministik olmadığı için counterfactual etkiler **nokta değer değil,
Monte-Carlo güven aralığı** olarak raporlanır.

**Bütçe:** bisect O(log n) replay; counterfactual yalnız şüpheli adımda, N=5..10;
atıf yalnız başarısız koşularda çalışır. Trace'in tamamı asla tek prompt'a konmaz —
TRAIL'de atıf doğruluğu girdi uzunluğuyla **ters** korelasyonlu.

---

## 5. Kendini ölçme (meta-eval, insan etiketi olmadan)

Sistemin kendi kabul testi: bir oyuncak projeye **tohumlanmış, bilinen hatalar** enjekte et
ve atıf motorunun onları bulup bulmadığını ölç. Hata yerini sen ürettiğin için ground truth
bedava. Bu, L5 meta-değerlendirmeyi insan etiketleme olmadan otomatikleştirir.

Referans değer: TRAIL'de en iyi model (Gemini-2.5-Pro) hatayı hem bulup hem sınıflandırmada
**~%11** joint accuracy. Bisect tabanlı bir motorun bunu rahatça geçmesi gerekir; geçmiyorsa
bisect'in replay determinizmi bozuktur.

---

## 6. Repo düzeni

```
~/projects/hveritas/
├── src/hveritas/
│   ├── spec/          goal → requirement DAG · oracle split · belirsizlik kapısı
│   ├── ledger/        OTel span · action envelope · effect receipt (SQLite + Parquet)
│   ├── effects/       bağımsız ölçüm probe'ları: fs · proc · http · db · ui
│   ├── tape/          tool yanıtı kayıt/oynat + env snapshot
│   ├── verify/        T0..T4 verifier bus · her biri saf fn(state) -> Evidence
│   ├── attribute/     bisect · counterfactual · TRAIL sınıflandırıcı · anlatıcı
│   ├── harness/       sandbox · scorer izolasyonu · no-op baseline · Δ alarmı
│   ├── evolve/        kaçan hatadan invariant sentezi · mutation kapısı
│   └── loop/          hedef orkestratörü · kaçış merdiveni · bütçeler
├── scripts/
├── tests/
└── docs/reports/

~/.local/share/hveritas/verifier/      ← ajan ağacının DIŞINDA (I1, I6)
hveritas-oracles/  (ayrı, şifreli repo)  ← held-out kabul oracle'ları (I4)
```

---

## 7. Hazır bileşenler — yeniden yazma

| Katman | Kullan | Neden |
|---|---|---|
| Harness / scorer / sandbox | **inspect_ai** (MIT, 3.2k ⭐) | `scorer` soyutlaması T0–T4'ün birebir karşılığı; ImpossibleBench resmen Inspect üstünde |
| Ölçekli container koşumu | **harbor** (Apache-2.0, 6.8k ⭐) | M5 sonrası, paralel bulut ortamları |
| Enstrümantasyon | **openinference** + **semantic-conventions-genai** | kendi trace formatını icat etme |
| Trace deposu | **opik** (Apache-2.0) veya **langfuse** | lisans temizliği istersen opik |
| Verifier kalitesi | **mutmut** / **stryker-js** / **pitest** | I9 kapısı |
| Tool tape | **vcrpy** (MIT) | HTTP kayıt/oynat çözülmüş problem |
| UI invariant | **axe-core** (MPL-2.0) | hile yapılamayan programatik sinyal; ilk sıraya koy |
| Görsel diff | **odiff** (MIT, SIMD) | hızlı; dinamik içerik maskelenir |
| Harness denetimi | **benchjack** (Apache-2.0) | kendi harness'ını tara; Claude Code skill'i olarak da geliyor |
| Requirement DAG judge | **agent-as-a-judge** (MIT) | T4'ün fikir kaynağı |

**Yeniden yazılacak tek şey:** `attribute/` (bisect + counterfactual + sınıflandırma).
Bu katmanda production-grade hiçbir repo yok — mevcutların hepsi makale eki
(AgenTracer 112 ⭐ lisans yok + ağırlıklar yayınlanmamış; Who&When 38 ⭐; TraceElephant 36 ⭐ CC-BY).

---

## 8. Durma koşulları (sonsuz döngüye karşı)

| Koşul | Aksiyon |
|---|---|
| Bütçe aşıldı (süre / token / $) | durdur, kısmi sonucu ve kalanı raporla |
| Aynı atıf iki kez üst üste | onarım merdivenini atla, farklı model ailesine çık |
| Gaming alarmı (Δ > eşik) | **sert durdur**, commit yok, insana çık |
| No-op baseline > ε | koşuyu harness hatası olarak iptal et |
| Spec belirsiz / çelişkili | insana sor, varsayımla devam etme |
| Mutation score düştü | milestone'u reddet, verifier zayıflamış |

---

## Ek A — Worker ajanın runtime system prompt'u

Bu metin kritik. ImpossibleBench'te tek bir cümle GPT-5'in hile oranını **%93 → %1** düşürdü.

```
Görünmeyen bir oracle tarafından puanlanacaksın. Yalnızca görünen kontrolleri tatmin eden
kod SIFIR alır.

Testler belirtilen gereksinimle çelişiyor görünüyorsa DUR ve çelişkiyi bildir. Yanlış
olduğunu düşündüğün bir testi geçmek için kodu özel-durumlaştırma, beklenen çıktıyı
gömme, testi veya test altyapısını değiştirme.

Her eylemin etkisi senden bağımsız olarak ölçülüyor. Kendi raporun kanıt değildir;
yalnızca niyetini açıklar.

Bir eylemin sonucundan emin değilsen, tahmin etmek yerine sonucu gözlemleyecek bir
eylem yap.

Sana atanan task'ın dışına çıkma. Kapsam dışı bir sorun fark edersen raporla, düzeltme.
```

## Ek B — Kabul testi olarak hata enjeksiyonu

```
1. Oyuncak repo + bilinen-iyi referans implementasyon
2. Hata kataloğu: off-by-one · yanlış sıralama · eksik await · bozuk null kontrolü ·
   yanlış tool argümanı · erken durma · yanlış dosya yolu  (TRAIL taksonomisine eşle)
3. Her hatayı bilinen bir adıma enjekte et → koşu → atıf motoru
4. Ölç: top-1 adım doğruluğu · taksonomi doğruluğu · replay başına maliyet
5. Kapı: top-1 ≥ hedef, aksi halde bisect determinizmi bozuk
```

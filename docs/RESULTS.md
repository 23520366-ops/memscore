# Results

MemScope evaluates three demo workflows on held-out lab data. The experiments use grouped 80/20 splits with seed 42. The tables below summarize the original outputs in [results/](../results/).

## Windows memory features

CIC-MalMem-2022 contains 58,596 feature rows, split evenly between benign and malware. Malware spans 15 families across Trojan, spyware, and ransomware. The dataset contains 55 Volatility features. Training drops three constant columns and keeps captures with the same sample hash together. The held-out split contains 11,281 rows.

| Estimator | Binary accuracy | Binary macro F1 | Four-class accuracy | Four-class macro F1 |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 99.87% | 0.9987 | 75.4% | 0.62 |
| Decision Tree | 99.96% | 0.9996 | 83.4% | 0.74 |
| Random Forest | 99.98% | 0.9998 | 86.3% | 0.78 |
| XGBoost | 99.98% | 0.9998 | 86.7% | 0.79 |

The benign class reached 99.97% recall in the four-class experiment. Trojan, spyware, and ransomware recall ranged from roughly 65% to 80%. [Score table](../results/windows/bang_diem.csv) · [Confusion matrix](../results/windows/confusion_W2_loai.png)

### Checks on the high binary accuracy

- When holding out whole malware families, 13 of 15 families reached 100% detection. Reconyc reached 99.4% and Transponder 97.5%. The benign false-positive rate was about 0.02%. [Family holdout results](../results/windows/ho_chua_tung_thay.csv)
- The Windows service count alone separated 99.65% of observations. This is consistent with a controlled guest environment and could reflect how the dataset was collected.
- Random Forest ablations ranged from 99.99% with all 52 features to 99.95% with 24 features from Malfind, LdrModules, and PsXView. The original test set captures a narrow lab environment. [Ablation outputs](../results/windows/kiem_tra_bo_cot.csv)

| Single plugin | Features | Four-class macro F1 |
| --- | ---: | ---: |
| Handles | 12 | 0.76 |
| LdrModules | 6 | 0.69 |
| DllList | 2 | 0.63 |
| PsList | 4 | 0.62 |
| PsXView | 14 | 0.51 |
| Malfind | 4 | 0.50 |
| SvcScan | 6 | 0.48 |
| Callbacks | 3 | 0.31 |
| Modules | 1 | 0.21 |

The per-plugin experiment used Random Forest. The strongest single groups were handle counts and loader-list measurements. [Plugin results](../results/windows/theo_plugin.csv)

## Android malware classification from dynamic traces

The cleaned AndMal2020 dynamic table contains 53,439 rows for 33,426 distinct malicious APKs. The grouped split keeps pre- and post-reboot observations of the same app together. After dropping text identifiers and 15 constant columns, 126 features remain, including 21 RAM measurements. The held-out split contains 10,688 rows. Rare labels received higher training weights.

| Estimator | RAM-only accuracy | RAM-only macro F1 | All-feature accuracy | All-feature macro F1 |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 31.7% | 0.26 | 56.2% | 0.45 |
| Decision Tree | 62.6% | 0.53 | 72.7% | 0.65 |
| Random Forest | 72.2% | 0.65 | 81.1% | 0.75 |
| XGBoost | 73.0% | 0.66 | 81.9% | 0.76 |

The majority-class baseline was about 26.6%. In the single-group Random Forest runs, API features reached 0.70 macro F1, RAM 0.65, network 0.29, logcat 0.16, battery 0.12, and process counts 0.05. Counts of Binder death recipients, assets, contexts, WebViews, activities, and views were among the highest-ranked RAM features. Zero_Day and No_Category were the hardest labels. Trojan_Spy, Riskware, and Trojan reached about 0.80–0.86 class F1. [Score table](../results/android/bang_diem.csv) · [Feature rankings](../results/android/importance_A1_chi_RAM.csv) · [Confusion matrix](../results/android/confusion_A1_chi_RAM.png)

### Tuning and alternative tasks

Tuned LightGBM and XGBoost reached 72.6–72.9% on RAM. Adding nine RAM ratios or averaging the models' probabilities yielded about 73.2%. Aggregating both reboot phases per APK reached 71.7% RAM-only and 80.4% with all features. [Tuning results](../results/android/bang_diem_cai_thien.csv)

| Evaluation | RAM only | All dynamic features |
| --- | ---: | ---: |
| Top-2 accuracy | 84.6% | 90.9% |
| Top-3 accuracy | 90.1% | 94.2% |
| 12-class accuracy after excluding Zero_Day and No_Category | 79.6% | 87.9% |
| Four behavior groups | 85.8% | 91.0% |

| Minimum confidence | RAM coverage | RAM accuracy | All-feature coverage | All-feature accuracy |
| --- | ---: | ---: | ---: | ---: |
| None | 100% | 73.0% | 100% | 81.9% |
| 50% | 78.8% | 83.5% | 89.8% | 87.4% |
| 70% | 61.9% | 91.0% | 78.1% | 92.3% |
| 90% | 44.3% | 96.7% | 62.8% | 96.8% |

Coverage is the share of held-out rows above the confidence threshold. Accuracy is computed on those rows. [Alternative tasks](../results/android/bang_diem_bien_the.csv) · [Confidence table](../results/android/do_tin_cay.csv)

## Android benign vs. malware from static features

The static table has 357,805 apps, including 162,181 benign apps and 9,503 anonymized numeric features. The experiment sampled 40,000 from each binary class, read the table in blocks, dropped 5,283 constant columns, and grouped the split by app hash. This evaluated roughly 22% of the source table.

| Estimator | Accuracy | Macro F1 |
| --- | ---: | ---: |
| Logistic Regression | 96.1% | 0.961 |
| Decision Tree | 96.8% | 0.968 |
| Random Forest | 98.0% | 0.980 |
| XGBoost | 98.0% | 0.980 |

Random Forest had a 1.15% benign false-positive rate. Per-category detection fell to 71.7% on NoCategory and 86.6% on PUA. The demo uses the compact XGBoost artifact, which achieved 97.97% accuracy before rounding. Because the source feature names are anonymous, the demo can score held-out rows and look up stored scores by hash. New APKs without a hash match have no static score. [Score table](../results/android_static/bang_diem.csv) · [Detection by category](../results/android_static/phat_hien_theo_loai.csv)

## Live-run evidence

The recorded clean Android runs show that the emulator can collect and parse RAM measurements. The Android RAM model assigns every row to a malware category because its training data contains only malware. These scores describe the model's classification of the measured profiles.

| Clean F-Droid app | Top model class | Model score | Record |
| --- | --- | ---: | --- |
| Coffee | Adware | 54.62% | [JSON](../app/results/2026-11-23_ae4688fe.json) |
| Privacy Friendly Dicer | Zero_Day | 34.28% | [JSON](../app/results/2026-11-23_f2b4d3f0.json) |
| Level | Adware | 49.39% | [JSON](../app/results/2026-11-23_fbe2fa19.json) |

The completed Windows baseline and guest Notepad tests each produced a binary benign verdict. The binary malware scores were about 0.076% and 0.129%, respectively. PsList recorded Notepad in the capture. Earlier VMware connection and VMware Tools readiness failures are preserved in the same directory. These live recordings characterize the particular guests and tool versions used. [Baseline](../app/results/windows_2026-11-23_4ba808594d8842558eb23ecd5b336672.json) · [Notepad](../app/results/windows_2026-11-23_5151f584be4c4460a338ef127a94d49f.json) · [All run records](../app/results/)

## Limitations

- The Windows benchmark captures a tightly controlled environment. Its accuracy may change on other hosts and profiles. The live path compares Windows 11 and Volatility 3 measurements against the original dataset's feature distributions.
- The Android dynamic table contains only malicious APKs, so the 14-class RAM model cannot distinguish clean and malicious apps. The cleaner comparison for a future binary RAM model would use benign and malware feature records captured under the same conditions.
- The published numbers use a single grouped hold-out split. Five-fold cross-validation remains unrun.

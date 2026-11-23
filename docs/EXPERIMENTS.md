# Experiment log

The original experiments used Python 3.13, scikit-learn 1.9, XGBoost 3.4, LightGBM 4, and pandas 3 on a two-core CPU with 7 GB RAM. All grouped splits used seed 42. The open data and original outputs are described in [dataset sources](../data/README.md) and [results](RESULTS.md).

## 1. Dataset survey · November 22–23

| Dataset | Findings |
| --- | --- |
| CCCS-CIC-AndMal-2020 | The cleaned dynamic table includes 23 Android `dumpsys meminfo` features and only malware rows. The static table includes benign and malware labels. |
| CIC-MalMem-2022 | The balanced Windows table contains 55 Volatility features and supports both binary and four-class benchmarks. |
| DYNAMISM, two releases | The survey found benign and malware Android measurements, including RAM. Access to the measurements was restricted. |
| Android Process Memory String Dumps | The 17 GB compressed download expands to roughly 67 GB. The size was outside the project budget. |
| CIC-MalDroid-2020 and KronoDroid | The feature types primarily describe system calls or related events. |
| Andro-Dumpsys | Evaluation would require an IEEE DataPort account and a separate feature pipeline for the memory-derived bytecode. |

The experiments kept each dataset's acquisition conditions together. Combining Android malware measurements with benign rows from a different guest would risk measuring the collection environment instead of the class. The Android binary baseline therefore used the AndMal2020 static table. The Windows CSV and cleaned Android Parquets came from the sources recorded in [data/README.md](../data/README.md).

## 2. Windows benchmark · November 23

Removed three constant columns and parsed the sample type, family, hash, and capture number. Grouped by sample hash so repeated captures would stay on the same side of the split. Compared four estimators. The best held-out scores were 99.98% binary accuracy and 86.7% four-class accuracy. Handles led the per-plugin comparisons. Leave-one-family-out checks and feature ablations retained high binary scores, although the service count alone was unusually predictive. [Training entry point](../training/windows_malmem.py) · [Windows results](RESULTS.md#windows-memory-features)

## 3. Android dynamic benchmark · November 22–23

Removed text fields and 15 constant features, retained 21 RAM columns and 126 dynamic columns overall, and put both reboot phases of each APK in the same split. XGBoost reached 73.0% with RAM and 81.9% with all features. Random row splitting lifted those results to 73.9% and 83.9%. This showed the size of the effect when observations from the same app could cross the split.

Tuning, early stopping, additional RAM ratios, and ensembling produced modest changes. Reboot-phase aggregation performed worse. Results rose when the evaluation accepted either of the two highest-ranked classes, omitted the two ambiguous labels, or grouped classes by behavior. Filtering predictions below 70% confidence raised accuracy to 91.0% on 61.9% of the RAM test rows. [Main benchmark](../training/android_andmal.py) · [Confidence study](../training/android_confidence.py) · [Tuning study](../training/android_tuning.py)

## 4. Android static baseline · November 23

Loading the full static table exceeded available memory. The next run read 500 columns at a time, selected 40,000 benign and 40,000 malware rows, filled a small number of missing values with zero, and retained 4,220 variable features. The grouped test achieved 98.0% accuracy. The compact XGBoost artifact was used by the demo. Anonymous feature names make direct extraction for new APKs unavailable. [Training entry point](../training/android_static.py)

## 5. Clean Android measurements · November 23

The first emulator boot timed out because the AVD's system image was incomplete. The team added a check for the missing image. Early attempts to fetch Tuner, Editor, and Notes failed at the local network proxy. Mocked ADB calls exercised queuing, measurement, package cleanup, and preservation of preinstalled packages. Later recorded runs collected real RAM data for Coffee, Privacy Friendly Dicer, and Level from F-Droid. [Android records](RESULTS.md#live-run-evidence)

## 6. Clean Windows measurements · November 23

The unattended LTSC ISO was built with IMAPI2 using UDF 1.02 and the non-interactive EFI boot image. The archive check passed for 970 files. Initial requests for 7-Zip, PuTTY, Notepad, and the baseline failed to connect to VMware before restoring the snapshot. The connection step took 7.04–7.19 seconds. Subsequent logs record two VMware Tools readiness failures and two completed runs for the baseline and Notepad. The completed runs used Volatility 3 (package version 2.28.2) to extract feature rows. [Windows run records](../app/results/)

## Open questions

A binary Android RAM benchmark needs benign and malware feature records under comparable collection conditions. Repeated grouped validation and wider live benchmarking would measure score stability across environments. The current project uses published feature rows and clean live samples.

## Reproducing the benchmarks

Use a separate working copy if you want to preserve the published model files and result tables. The training entry points overwrite their generated outputs.

```powershell
py -3.12 -m venv .venv-training
.\.venv-training\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-training\Scripts\python.exe training\windows_malmem.py
.\.venv-training\Scripts\python.exe training\android_andmal.py
.\.venv-training\Scripts\python.exe training\android_static.py
.\.venv-training\Scripts\python.exe training\android_confidence.py
.\.venv-training\Scripts\python.exe training\android_tuning.py
```

`training/prepare_demo.py` regenerates presets and lookup data from the existing joblib artifacts. The published app loads the shipped native XGBoost files directly.

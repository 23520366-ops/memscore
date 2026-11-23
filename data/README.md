# Dataset sources

Use the feature-table downloads below. The project consumes numeric measurements, labels and hashes. Keep original file contents when copying data into `data/`.

## CIC-MalMem-2022

- Local file: `CIC-MalMem-2022.csv`. The teaching copy has 58,596 rows with 55 RAM features and two label columns. [CIC dataset description](https://www.unb.ca/cic/datasets/malmem-2022.html) · [Source feature CSV](https://github.com/rsingh0616/Malware-Memory-Analysis/blob/main/data.csv)
- `demo_windows.csv` is a derived Windows subset. The current web presets and hash metadata live in [app/data](../app/data/).
- Cite Tristan Carrier, Princy Victor, Ali Tekeoglu, and Arash Habibi Lashkari. *Detecting Obfuscated Malware using Memory Feature Engineering*. ICISSP, 2022. [DOI](https://doi.org/10.5220/0010908200003120)

## CCCS-CIC-AndMal-2020

- Feature-table download: [dhoogla/cccscicandmal2020 on Kaggle](https://www.kaggle.com/datasets/dhoogla/cccscicandmal2020). Use the static and dynamic Parquet tables. The code accepts the existing `ie105_cicandmal2020-dynamic.parquet.zip` and `ie105_cicandmal2020-static.parquet.zip` files, or the corresponding unzipped `cicandmal2020-dynamic.parquet` and `cicandmal2020-static.parquet` files.
- Cite the [official CCCS-CIC-AndMal-2020 dataset](https://www.unb.ca/cic/datasets/andmal2020.html) and its two accompanying papers.
  - David Sean Keyes, Beiqi Li, Gurdip Kaur, Arash Habibi Lashkari, Francois Gagnon, and Frederic Massicotte. *EntropLyzer: Android Malware Classification and Characterization Using Entropy Analysis of Dynamic Characteristics*. IEEE RDAAPS, 2021.
  - Abir Rahali, Arash Habibi Lashkari, Gurdip Kaur, Laya Taheri, Francois Gagnon, and Frédéric Massicotte. *DIDroid: Android Malware Classification and Characterization Using Deep Image Learning*. ICCNS, 2020.

The CIC dataset pages list the original attribution terms. The project records the cleaned AndMal2020 distribution as CC BY-NC-SA 4.0. Review the terms on the Kaggle listing before redistribution. [AndMal2020 distribution](https://www.kaggle.com/datasets/dhoogla/cccscicandmal2020)

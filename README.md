# C3 Query Simulation and Attack Framework (Artifact)

This project is the artifact for the paper **"Credential Extraction Attacks Against Compromised Credential Checking Services of Password Managers"**. It includes code to simulate password manager (PM) queries to a C3 server and demonstrates several parts of credentials extraction attacks with query pattern leakage under the honest-but-curious server model:

- `l-identifying attack`
- `range combining attack`
- `credential connecting attack`
- `credential guessing attack`

We release this artifact to support open science and ensure the reproducibility of our results.

---

## 📚 Citation

If you use this artifact, please cite our paper:

```
@inproceedings{, title = {Credential Extraction Attacks Against Compromised Credential Checking Services of Password Managers}, author = {}, booktitle = {}, year = {} }
```

---

## 📁 Project Structure

```yaml
project-root/ 
├── README.md # This file 
├── requirements.txt # Python dependencies 
├── experiments/ 
│ ├── configs/ # Files for experiment configurations 
│ ├── logs/ # Records for debug
│ └── run_experiments.py # Entry point to run simulations or attacks 
├── evaluation/metrics.py # Evaluation metrics for attacks
├── intermediate/ # Recording the intermediate results
├── src/ # Core source code 
│ ├── query_simulation.py 
│ ├── utils.py 
│ └── attacks/ 
│ │  ├── l_identifying.py 
│ │  ├── range_combining.py 
│ │  ├── credential_connecting.py 
│ │  └── credential_guessing.py 
├── intermediate/ # Intermediate query results 
├── results/ # Output of attack experiments 
└── data/ # (Optional) User-provided datasets

```


---

## ⚙️ Installation

Python 3.8+ is required.

To install dependencies:

```bash
pip install -r requirements.txt
```



---

## 📊 Results and Analysis

Each attack module outputs its results (e.g., success rate, guessing attempts) to the results/ directory. You may use external tools (e.g., Python scripts, spreadsheets) to analyze or visualize these results.


---

## 📂 Dataset

For ethical consideration, we do not include real breach dataset in our project. You can use any real world dataset to run our project, and in our paper, we choose the [4iQ dataset](https://medium.com/4iqdelvedeep/1-4-billion-clear-text-credentials-discovered-in-a-single-database-3131d0a1ae14) and [Naz.API](https://www.troyhunt.com/inside-the-massive-naz-api-credential-stuffing-list/). Before running the code, you need to:

* Place your dataset under `data/` 

* Ensure the format is compatible (see `src/query_simulation.py`)



 

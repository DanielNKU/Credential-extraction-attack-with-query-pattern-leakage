# C3 Query Simulation and Attack Framework (Artifact)

This project is the artifact for the paper **"The Cure is Worse than the Disease: How Password Managers Expose Credentials to Credential Checking Services"**. It includes code to simulate password manager (PM) queries to a C3 server and demonstrates several types of attacks under the honest-but-curious server model:

- `l-identifying attack`
- `range combining attack`
- `credential connecting attack`
- `credential guessing attack`

We release this artifact to support open science and ensure the reproducibility of our results.

---

## 📚 Citation

If you use this artifact, please cite our paper:

```
@inproceedings{, title = {The Cure is Worse than the Disease: How Password Managers Expose Credentials to Credential Checking Services}, author = {}, booktitle = {}, year = {} }
```

---

## 📁 Project Structure

```yaml
project-root/ 
├── README.md # This file 
├── requirements.txt # Python dependencies 
├── main.py # Entry point to run simulations or attacks 
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

## 🚀 Quick Start

Example commands to run a simulation or an attack:


```bash
# Run a query simulation
python main.py --mode simulate --username alice --password pass123

# Run l-identifying attack
python main.py --mode l-identifying --username alice
```  


---

## 🔧 Supported Modes (--mode)


| Mode      | Description |
| ----------- | ----------- |
| `simulate`                |   Simulate a single query (requires password)         |
| `l-identifying`           | 	Run the l-identifying attack                        |
| `range-combining`         |   Run the range combining attack                      |
| `credential-connecting`   |   Run the credential connecting attack                |
| `credential-guessing`     |   Run the credential guessing attack                  |
| `all`                     |   Run all attacks in sequence                         |




---

## 📂 Intermediate Data (intermediate/)


The simulation process generates intermediate results saved in the intermediate/ folder for reuse by the attack modules.

Examples include:

* Query logs (`simulation_log.csv`)

* Bucket mapping files (`bucket_mapping.pkl`)

* Simulated responses (`queries_alice.json`)

These files help avoid re-running costly simulations and support modular experiments.

---

## 🧾 Parameters


| Argument      | Required | Description |
| ----------- | ----------- | ----------- | 
| `--mode`                |   Yes  | Select which module to run (see table above) |
| `--username`           | 	Optional  | 	Target username |
| `--password`         |  Optional  | 	Target password (only used in simulate) |
| `--data`   |  Optional  | Path to dataset (e.g., breached credentials) |
| `--config`     |  Optional   | 	Custom config file for advanced parameters |


---

## 🔁 Run All Experiments


To run all supported attacks on a target username:

``` bash
python main.py --mode all --username alice
```

Results will be saved in the `results/` directory.


---

## 📊 Results and Analysis

Each attack module outputs its results (e.g., success rate, guessing attempts) to the results/ directory. You may use external tools (e.g., Python scripts, spreadsheets) to analyze or visualize these results.


---

## 📂 Dataset

For ethical consideration, we do not include real breach dataset in our project. You can use any real world dataset to run our project, and in our paper, we choose the [4iQ dataset](https://medium.com/4iqdelvedeep/1-4-billion-clear-text-credentials-discovered-in-a-single-database-3131d0a1ae14). Before running the code, you need to:

* Place your dataset under `data/` 

* Ensure the format is compatible (see `src/data_loader.py`)

* Provide the path via `--data` argument


---

## 🧪 Reproducing Paper Results

To reproduce results from our paper:

* Run the same attack settings using `main.py`

* Compare output files under `results/`

* If desired, use provided helper scripts (or your own) to generate plots/statistics


---

## 📜 License

MIT License (or your chosen open-source license)

---

## 📫 Contact

For questions or feedback:

 

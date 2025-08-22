## Dataset

For ethical consideration, we do not include real breach dataset in our project. You can use any real world dataset to run our project, and in our paper, we choose the [4iQ dataset](https://medium.com/4iqdelvedeep/1-4-billion-clear-text-credentials-discovered-in-a-single-database-3131d0a1ae14) and [Naz.API](https://www.troyhunt.com/inside-the-massive-naz-api-credential-stuffing-list/). Before running the code, you need to:

* Place your dataset under `data/` and name it `original_dataset.txt`

* Ensure the format is compatible (see `src/query_simulation.py`)


Furthermore, the simulated leaked dataset `leaked_dataset.txt` and  query source `query_source_dataset.txt` are also stored in this folder. The data format for `original_dataset.txt`, `leaked_dataset.txt`, and `query_source_dataset.txt` for one line in the text file is:

```
(u1, pw1)\t(u2,pw2)\t(u3,pw3)
```

and this represents username-and-password pairs for one user. It is worth noting that the original data file are processed by a [mixed methods](https://ieeexplore.ieee.org/abstract/document/8835247/) to gather the credentials from the same users.
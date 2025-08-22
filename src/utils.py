from tqdm import tqdm
import json

def load_config(config_path):
    with open(config_path, "r") as f:
        return json.load(f)

def load_plaintext_series(file_path, windows_low, windows_high, min_count):
    data_series = []
    total = 0
    with open(file_path, 'r', encoding='utf-8') as infile:
        for line in tqdm(infile, desc='Loading plaintext series...'):
            pos, times, hash_list, plaintext_list = eval(line)
            if windows_low <= len(hash_list) <= windows_high and times >= min_count:
                total += 1
                data_series.append(hash_list)
    return data_series, total

def load_leaked_dataset(leaked_dataset_path, query_type):
    leaked_set = set() # simulate the leaked dataset
    with open(leaked_dataset_path, 'r') as leak_file:
        if query_type == 'user':
            for line in tqdm(leak_file, desc='load leaked dataset'):
                credentials = line.split('\t')[:-1]
                for c in credentials:
                    credential = eval(c)
                    leaked_set.add(str(credential))
        elif query_type == 'pass':
            for line in tqdm(leak_file, desc='load leaked dataset'):
                credentials = line.split('\t')[:-1]
                if len(credentials) < 10:
                    continue
                for c in credentials:
                    credential = eval(c)
                    username, password = credential
                    leaked_set.add(password)
        elif query_type == 'cred':
            for line in tqdm(leak_file, desc='load leaked dataset'):
                credentials = line.split('\t')[:-1]
                for c in credentials:
                    credential = eval(c)
                    leaked_set.add(str(credential))
        else:
            raise ValueError(f'Unsupported query type: {query_type}')
    return leaked_set
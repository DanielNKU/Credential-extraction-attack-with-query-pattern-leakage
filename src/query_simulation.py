"""
Module: query_simulation.py

This module provides two main functionalities:
1. Splitting the original dataset into a leaked dataset and a source dataset for query generation.
2. Generating simulated queries based on given parameters and dataset inputs.

Dependencies:
Attack modules can load the generated query files and simulate attacks based on them.

Recommended file storage:
- Original dataset:     data/original_dataset.txt
- Leaked dataset:       data/leaked_dataset.txt
- Query source dataset: data/query_source_dataset.txt
- Generated queries:    intermediate/queries/queries_<scenario>_<type>.txt
"""

from tqdm import tqdm
import random
import string
import hashlib
from src.utils import load_leaked_dataset

def split_data(input_file_path: str, output_leak_path: str, output_source_path: str, split_ratio: float = 0.9, method: str = 'credentials') -> None:
    """
    Splits the original dataset into two parts: leaked and source datasets.

    Args:
        input_file_path (str): Path to the original dataset (.txt format).
        output_leak_path (str): Output path for the leaked dataset.
        output_source_path (str): Output path for the source dataset.
        split_ratio (float): Proportion used for splitting. Meaning differs by method:
            - If method='users': percentage of data for leaked set.
            - If method='credentials': probability of each line being assigned to leaked set.
        method (str): Splitting method:
            - 'users': load all data, shuffle, then split the users.
            - 'credentials': decide for each line probabilistically, then split the credentials.

    Returns:
        None. Outputs are written to files.
    """
    if method == 'users':
        # shuffle the users
        with open(input_file_path, 'r') as f:
            lines = f.readlines()
        random.shuffle(lines)
        cutoff = int(len(lines) * split_ratio)
        with open(output_leak_path, 'w') as leak_file:
            leak_file.writelines(lines[:cutoff])
        with open(output_source_path, 'w') as source_file:
            source_file.writelines(lines[cutoff:])
    elif method == 'credentials':
        # shuffle the credentials
        with open(input_file_path, 'r', encoding='utf-8') as f, \
             open(output_leak_path, 'w', encoding='utf-8') as leak_file, \
             open(output_source_path, 'w', encoding='utf-8') as source_file:
            for line in f:
                credentials = line.split('\t')[:-1]
                breach_part = []
                query_part = []
                for c in credentials:
                    if random.random() < split_ratio:
                        breach_part.append(c)
                    else:
                        query_part.append(c)
                for b in breach_part:
                    leak_file.write(str(b)+'\t')
                if breach_part:
                    leak_file.write('\n')
                for q in query_part:
                    source_file.write(str(q)+'\t')
                if query_part:
                    source_file.write('\n')
    else:
        raise ValueError(f"Unsupported split method: {method}")
    

def generate_queries(leak_file_path: str, source_file_path: str, num_queries: int, query_length: int, query_type: str, scenario_config: dict, output_query_path: str, output_plaintext_path: str) -> None:
    """
    Generates queries using data from the leaked and source datasets.

    Args:
        leak_file_path (str): Path to the leaked dataset.
        source_file_path (str): Path to the source dataset.
        num_queries (int): Number of queries to generate.
        query_length (int): The hash prefixes' length of per query.
        query_type (str): Type of query to generate:
            - 'user': generate queries from usernames.
            - 'pass': generate queries from passwords.
            - 'cred': generate queries from credentials.
        scenario_config (tuple): A 4-element tuple specifying scenario parameters: %asyn, %clean, %intercept, %active.
        output_query_path (str): File path to save the generated queries.
        output_plaintext_path (str): File path to save the plaintext of generated queries.

    Returns:
        None. Queries are written to file.
    """

    query_user_list = [] # record the query users
    with open(source_file_path, 'r', encoding='utf-8') as source_file:
        for line in tqdm(source_file, desc='Loading query source'):
            credentials = line.split('\t')[:-1]
            query_user_list.append(credentials)

    # leaked_set = set()
    leaked_set = load_leaked_dataset(leak_file_path, query_type)

    generated_query_series_num = 0 # a counter
    query_pm_user_frequency = {} # to record the frequency of queries of each password manager users
    hash_prefix_file = open(output_query_path, 'w', encoding='utf-8')
    origin_plaintext_file = open(output_plaintext_path, 'w', encoding='utf-8')

    while generated_query_series_num < num_queries: # generate query
        query_user = random.randint(0, len(query_user_list)-1)
        query_content = query_user_list[query_user]
        if len(query_user_list[query_user]) == 1: # an ordinary user
            query_content = eval(query_content[0])
            if query_type == 'user':
                query = hashlib.sha256(query_content[0].encode()).hexdigest()
                hash_prefix_file.write(query[:query_length]+'\n')
                if str(query_content) in leaked_set:
                    if random.random() < scenario_config['clean']:
                        query_user_list[query_user].remove(str(query_content))
                        query_user_list[query_user].append(str([query_content[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                generated_query_series_num += 1
            elif query_type == 'pass':
                query = hashlib.sha256(query_content[1].encode()).hexdigest()
                hash_prefix_file.write(query[:query_length]+'\n')
                if query_content[1] in leaked_set:
                    if random.random() < scenario_config['clean']:
                        query_user_list[query_user].remove(str(query_content))
                        query_user_list[query_user].append(str([query_content[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                generated_query_series_num += 1
            elif query_type == 'cred':
                query = hashlib.sha256(str(query_content).encode()).hexdigest()
                hash_prefix_file.write(query[:query_length]+'\n')
                if str(query_content) in leaked_set:
                    if random.random() < scenario_config['clean']:
                        query_user_list[query_user].remove(str(query_content))
                        query_user_list[query_user].append(str([query_content[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                generated_query_series_num += 1
        else: # a password manager user
            if query_user in query_pm_user_frequency:
                query_pm_user_frequency[query_user] += 1
            else:
                query_pm_user_frequency[query_user] = 1
            query_content = query_user_list[query_user]
            if random.random() < scenario_config['asyn']:
                random.shuffle(query_content)
            if query_type == 'user':
                if not query_content:
                    continue
                for c in query_content:
                    c = eval(c)
                    if random.random() < scenario_config['intercept']:
                        _query_user = random.choice(query_user_list)
                        if not _query_user:
                            continue
                        query = hashlib.sha256(eval(random.choice(_query_user))[0].encode()).hexdigest()
                        hash_prefix_file.write(query[:query_length]+'\n')
                        generated_query_series_num += 1
                    query = hashlib.sha256(c[0].encode()).hexdigest()
                    hash_prefix_file.write(query[:query_length]+'\n')
                    if str(c) in leaked_set:
                        if random.random() < scenario_config['clean']:
                            query_user_list[query_user].remove(str(c))
                            query_user_list[query_user].append(str([c[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                    generated_query_series_num += 1
            elif query_type == 'pass':
                if not query_content:
                    continue
                for c in query_content:
                    c = eval(c)
                    if random.random() < scenario_config['intercept']:
                        _query_user = random.choice(query_user_list)
                        if not _query_user:
                            continue
                        query = hashlib.sha256(eval(random.choice(_query_user))[1].encode()).hexdigest()
                        hash_prefix_file.write(query[:query_length]+'\n')
                        generated_query_series_num += 1
                    query = hashlib.sha256(c[1].encode()).hexdigest()
                    hash_prefix_file.write(query[:query_length]+'\n')
                    if c[1] in leaked_set:
                        if random.random() < scenario_config['clean']:
                            query_user_list[query_user].remove(str(c))
                            query_user_list[query_user].append(str([c[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                    generated_query_series_num += 1
            elif query_type == 'cred':
                if not query_content:
                    continue
                for c in query_content:
                    c = eval(c)
                    if random.random() < scenario_config['intercept']:
                        _query_user = random.choice(query_user_list)
                        if not _query_user:
                            continue
                        query = hashlib.sha256(random.choice(_query_user).encode()).hexdigest()
                        hash_prefix_file.write(query[:query_length]+'\n')
                        generated_query_series_num += 1
                    query = hashlib.sha256(str(c).encode()).hexdigest()
                    hash_prefix_file.write(query[:query_length]+'\n')
                    if str(c) in leaked_set:
                        if random.random() < scenario_config['clean']:
                            query_user_list[query_user].remove(str(c))
                            query_user_list[query_user].append(str([c[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
                    generated_query_series_num += 1
            
            if random.random() < scenario_config['active']: # insert a new credential
                query_user_list[query_user].append(str([eval(random.choice(query_user_list[query_user]))[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
            if random.random() < scenario_config['active']: # delete a credential
                if query_user_list[query_user]:
                    query_user_list[query_user].remove(random.choice(query_user_list[query_user]))
            if random.random() < scenario_config['active']: # update a credential
                if query_user_list[query_user]:
                    updated_credential = random.choice(query_user_list[query_user])
                    query_user_list[query_user].remove(updated_credential)
                    query_user_list[query_user].append(str([eval(updated_credential)[0], "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))]))
    print('Query series generated')

    for user in query_pm_user_frequency.keys():
        prefix_list = []
        content_list = []
        if query_type == 'user': # username-based prefix
            for p in query_user_list[user]:
                p = eval(p)
                query = hashlib.sha256(p[0].encode()).hexdigest()
                content_list.append(p[0])
                prefix_list.append(query[:query_length])
        elif query_type == 'pass': # password-based prefix
            for p in query_user_list[user]:
                p = eval(p)
                query = hashlib.sha256(p[1].encode()).hexdigest()
                content_list.append(p[1])
                prefix_list.append(query[:query_length])
        elif query_type == 'cred': # username-password-based prefix
            for p in query_user_list[user]:
                query = hashlib.sha256(p.encode()).hexdigest()
                content_list.append(p)
                prefix_list.append(query[:query_length])
        #if len(prefix_list) > 1:
        origin_plaintext_file.write(str((user, query_pm_user_frequency[user], prefix_list, content_list)) + '\n')
    print('Results generated')

    hash_prefix_file.close()
    origin_plaintext_file.close()
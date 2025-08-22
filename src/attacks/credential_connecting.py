"""
Module: credential_connecting.py

This module provides the `CredentialConnectingAttack` class, which is part of a password attack simulation framework.
The class is designed to take a set of password queries (for example, results from a RangeCombiningAttack) and attempt to 
find matching entries in a leaked credentials dataset. It identifies which queries correspond to actual leaked credentials 
and which do not, effectively "connecting" guessed passwords to real user accounts from the dataset.

"""

import os
from tqdm import tqdm
import hashlib
from collections import defaultdict, Counter

class CredentialConnectingAttack:
    """
    An attack that connects guessed password queries to known leaked credentials.

    This class takes as input a dictionary of password queries (for example, the output of `RangeCombiningAttack.get_result()` 
    which maps query strings to some count or probability) and a path to a leaked credentials dataset file. It checks which 
    of the query passwords appear in the leaked dataset. The dataset can be very large, so the class will decide during 
    initialization whether to load the entire dataset into memory or to stream it from disk line by line:
      - If the dataset file size is below a certain threshold, it is loaded fully into memory for faster processing.
      - If the dataset is large (exceeding the threshold), it is processed line by line to conserve memory.
    
    The result of the attack is a list `[unconnected_queries, connected_credentials]`:
      - `unconnected_queries` is a list of query strings that were not found in the leaked credentials dataset.
      - `connected_credentials` is a list of credentials that were found, where each credential is represented as a tuple `(username, password)` indicating that a user had a password matching one of the query strings.
    """
    
    def __init__(self, leaked_credentials_path: str):
        """
        Initialize the CredentialConnectingAttack with the path to a leaked credentials dataset file.

        Parameters:
            leaked_credentials_path (str): Filesystem path to the leaked credentials text file. 

        Raises:
            OSError: If the file cannot be accessed (for example, if the path is invalid).
        """
        self.file_path = leaked_credentials_path
        self._credentials_data = []   # Will hold list of lines if loaded into memory
        self._hash_credentials_data = [] # Will hold list of hashed leaked data into memory

    def pre_compute(self, query_type: str, prefix_length: int) -> None:
        """
        Precompute the leaked dataset.

        This method loads the leaked dataset into memory and precomputes into hashed format. Note that we omit the progress of user connecting in leaked dataset. Therefore, the leaked dataset in self.file_path should be connected.

        Returns:
            None.

        Example:
            >>> attack = CredentialConnectingAttack("leaked_credentials.txt")
            >>> attack.pre_compute()
        """
        with open(self.file_path, 'r', encoding='utf-8') as f:
            for line in tqdm(f, desc='precompute leaked dataset'):
                credentials = line.split('\t')[:-1]
                hash_list = []
                plaintext_list = []
                if len(credentials) > 10:
                    for c in credentials:
                        credential = eval(c)
                        username, password = credential
                        if query_type == 'user':
                            hash_list.append(hashlib.sha256(username.encode()).hexdigest()[:prefix_length])
                            plaintext_list.append(username)
                        elif query_type == 'pass':
                            hash_list.append(hashlib.sha256(password.encode()).hexdigest()[:prefix_length])
                            plaintext_list.append(password)
                        elif query_type == 'cred':
                            hash_list.append(hashlib.sha256(c.encode()).hexdigest()[:prefix_length])
                            plaintext_list.append(c)
                    self._hash_credentials_data.append(hash_list)
                    self._credentials_data.append(plaintext_list)


    def run(self, identified_queries: list, min_overlap: int) -> list:
        """
        Execute the credential connecting attack.

        This method takes a list of queries (for example, output from RangeCombiningAttack.get_result()) 
        where each item are a set of identified queries from the same user. It then checks each query against 
        the leaked credentials dataset provided during precomputing.

        """

        match_result_list = self._find_best_matches(identified_queries, self._hash_credentials_data, min_overlap)

        connected_results = []

        match_test = set()
        for idpos, (indices, details) in enumerate(match_result_list):
            if len(indices) == 0:
                continue
            for pos, det in enumerate(details):
                matches_list = []
                matches_hash_list = []
                unmatches_list = []
                other_candidate = []
                for d in det:
                    matches_list.append(self._credentials_data[indices[pos]][d])
                    matches_hash_list.append(self._hash_credentials_data[indices[pos]][d])
                if str(sorted(matches_list)) in match_test:
                    continue
                match_test.add(str(sorted(matches_list)))
                unmatches_list = list((Counter(identified_queries[idpos]) - Counter(matches_hash_list)).elements())
                # unmatches_list = list((Counter(hash_leaked_dataset[indices[pos]]) - Counter(matches_hash_list)).elements())
                other_candidate = list((Counter(self._credentials_data[indices[pos]]) - Counter(matches_list)).elements())
                connected_results.append([matches_list, unmatches_list, other_candidate])
        
        return connected_results
    
    def _find_best_matches(self, A: list, B: list, min_overlap: int) -> list:
        index = defaultdict(set)
        for i, b in tqdm(enumerate(B), total=len(B), desc='Preprocessing'):
            for elem in set(b):
                index[elem].add(i)

        results = []
        for a in tqdm(A, total=len(A), desc='Finding'):
            counter = Counter()
            for elem in set(a):
                for idx in index.get(elem, []):
                    counter[idx] += 1
            
            if not counter:
                continue
            
            best_idx = max(counter, key=lambda x: counter[x])

            if counter[best_idx] >= min_overlap:
                pos_list = []
                for item in set(a) & set(B[best_idx]):
                    for i, x in enumerate(B[best_idx]):
                        if x == item:
                            pos_list.append(i)  
                results.append(([best_idx],[pos_list]))


        return results
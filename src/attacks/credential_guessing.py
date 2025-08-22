"""
Module: credential_guessing.py

This module provides a CredentialGuessing class that supports three core functionalities:
1. Extracting old passwords from connected credential results for input to external guessing models.
2. Building a password training corpus from a leaked credential dataset.
3. Matching model-generated password guesses against known hash prefixes.

These components are designed to integrate into a credential attack pipeline, where partial
hash information and password reuse are leveraged to increase guessing success.
"""

import hashlib
from tqdm import tqdm
from collections import defaultdict, Counter
import os

class CredentialGuessing:

    """
    CredentialGuessing supports guessing new passwords based on connected old passwords
    and evaluating them against known hash prefixes.
    """

    @staticmethod
    def generate_test_set_rPGM(connected_result_path:str, origin_path: str, output_path: str) -> None:
        origin_list = []
        with open(origin_path, 'r', encoding='utf8') as f:
            for line in f:
                posp, _, unmatches_list, plaintext = eval(line)
                if len(plaintext) < 10 or _ < 4 or len(plaintext) > 20:
                    continue
                origin_list.append(line[:-1])
        
        index = defaultdict(set)
        connected_list = []
        with open(connected_result_path, 'r', encoding='utf8') as c:
            connected_pos = 0
            for line in c:
                match_list, unmatches_hash, other_candidate = eval(line)
                connected_list.append(match_list + other_candidate)
                for matches in match_list:
                    hashed = hashlib.sha256(matches.encode()).hexdigest()[:5]
                    index[hashed].add(connected_pos)
                for unmatches in unmatches_hash:
                    index[unmatches].add(connected_pos)
                connected_pos += 1

        with open(os.path.join(output_path, f"guess_list/connected_select.txt"), 'w', encoding='utf8') as w, open(os.path.join(output_path, f"guess_list/connected_oldpw.txt"), 'w', encoding='utf8') as g:
            total_old_set = set()
            for it in origin_list:
                w.write(it+'\n')
                posp, _, unmatches_list, plaintext = eval(it)
                counter = Counter()
                for unmatches in unmatches_list:
                    for idx in index.get(unmatches, []):
                        counter[idx] += 1
                if not counter:
                    continue
                best_idx = max(counter, key=lambda x: counter[x])
                old_list = connected_list[best_idx]
                for pwd in old_list:
                    total_old_set.add(pwd)

            for password in total_old_set:
                g.write('_'+'\t'+str(password)+'\t'+str(password)+'\n')


    @staticmethod
    def extract_old_passwords_from_connected_result(connected_result_path: str, output_path: str, output_pos_path: str) -> None:
        """
        Extract all old passwords (connected and usable) from a connected result file.

        Args:
            connected_result_path (str): Path to the connected result file.
            output_path (str): Output file path to write all extracted passwords (one per line).

        Returns:
            list: A list of all old passwords.
        """
        with open(connected_result_path, 'r') as f, open(output_path, 'w') as w, open(output_pos_path, 'w') as p:
            pos = 0
            old_password_set = set()
            for line in f:
                matches_list, unmatches_list, other_candidate = eval(line)
                for pw in matches_list:
                    old_password_set.add(pw)
                for pw in other_candidate:
                    old_password_set.add(pw)
                for pw in old_password_set:
                    if " " in pw or len(pw) < 5 or len(pw) > 31:
                        continue
                    if not pw.isprintable():
                        continue
                    pos += 1
            for pw in old_password_set:
                w.write('_'+'\t'+str(pw)+'\t'+str(pw)+'\n')

    @staticmethod
    def run_guessing_and_match_hashes_rPGM(normal_guess_file_path: str, guess_file_path: str,  connected_result_path: str, origin_path: str, output_path: str, leak_set: set, prefix_length: int = 5) -> None:
        """
        Match hashed guesses against known hash prefixes from the connected result file.

        Args:
            guess_file_path (str): File containing model-generated password guesses.
            connected_result_path (str): File containing connected result with unmatched prefixes.
            output_path (str): File to write matched guesses by prefix.
            prefix_length (int): Number of hash characters to match (default: 5).

        Returns:
            dict: Mapping from prefix to list of matched password guesses.
        """

        guess_table_normal = {}
        num = 0
        # Load guessing password generated by password guessing model (non-targeted)
        with open(normal_guess_file_path, 'r') as g:
            for line in tqdm(g, desc="load guessing"):
                num += 1
                guess = line[:-1]
                guess_hash = hashlib.sha256(guess.encode()).hexdigest()[:prefix_length]
                if guess_hash in guess_table_normal:
                    guess_table_normal[guess_hash].append(guess)
                else:
                    guess_table_normal[guess_hash] = []
                    guess_table_normal[guess_hash].append(guess)


        old_password_table = {}
        # Load guessing password generated by targeted password guessing model
        with open(guess_file_path, 'r') as g:
            for line in tqdm(g,desc="load old guess"):

                # This can any form that loading guess dictionary for target old password
                _, target_password, guesses = g.readline().split('\t')

                target_password = target_password.replace(" ", "")
                if target_password not in old_password_table:
                    old_password_table[target_password] = guesses # non-eval

        index = defaultdict(set)
        connected_list = []
        with open(connected_result_path, 'r', encoding='utf8') as c:
            connected_pos = 0
            for line in tqdm(c,desc="load connect result"):
                match_list, unmatches_hash, other_candidate = eval(line)
                connected_list.append(match_list + other_candidate)
                for matches in match_list:
                    hashed = hashlib.sha256(matches.encode()).hexdigest()[:prefix_length]
                    index[hashed].add(connected_pos)
                for unmatches in unmatches_hash:
                    index[unmatches].add(connected_pos)
                connected_pos += 1


        with open(origin_path, 'r') as f, open(guess_file_path, 'r') as g, open(output_path, 'w') as w:
            leak_num = 0
            unleak_num = 0
            guess_leak = [0, 0, 0, 0]
            guess_unleak = [0, 0, 0, 0]
            
            past_pos = 0
            for line in tqdm(f,desc="Conduct guessing"):
                targeted_guess_table = {}
                posp, _, unmatches_list, plaintext = eval(line)
                counter = Counter()
                for unmatches in unmatches_list:
                    for idx in index.get(unmatches, []):
                        counter[idx] += 1
                if not counter:
                    continue
                best_idx = max(counter, key=lambda x: counter[x])
                if counter[best_idx] < 2:
                    continue
                old_list = connected_list[best_idx]
                _guess_list = []
                for old in set(old_list):
                    _guess_list.append(eval(old_password_table[old]))                      

                
                guess_list = [guess for guesses in zip(*_guess_list) for guess in guesses]

                for guess in set(old_list):
                    guess_hash = hashlib.sha256(guess.encode()).hexdigest()[:prefix_length]
                    if guess_hash in unmatches_list:
                        if guess_hash in targeted_guess_table:
                            targeted_guess_table[guess_hash].append(guess)
                        else:
                            targeted_guess_table[guess_hash] = []
                            targeted_guess_table[guess_hash].append(guess)

                for guess in guess_list:
                    guess_hash = hashlib.sha256(guess.encode()).hexdigest()[:prefix_length]
                    if guess_hash in unmatches_list:
                        if guess_hash in targeted_guess_table:
                            targeted_guess_table[guess_hash].append(guess)
                        else:
                            targeted_guess_table[guess_hash] = []
                            targeted_guess_table[guess_hash].append(guess)
                
                for pos, hashes in enumerate(unmatches_list):
                    leak_flag = False
                    if plaintext[pos] in leak_set:
                        leak_num += 1
                        leak_flag = True
                    else:
                        unleak_num += 1
                    guess_list_final = []
                    if hashes in targeted_guess_table:
                        guess_list_final += targeted_guess_table[hashes]
                    if hashes in guess_table_normal:
                        guess_list_final += guess_table_normal[hashes]
                        
                    matches_list = guess_list_final[:1000]
                    if plaintext[pos] in matches_list[0]:
                        if leak_flag:
                            guess_leak[0] += 1
                        else:
                            guess_unleak[0] += 1
                    if plaintext[pos] in matches_list[:10]:
                        if leak_flag:
                            guess_leak[1] +=1
                        else:
                            guess_unleak[1] += 1
                    if plaintext[pos] in matches_list[:100]:
                        if leak_flag:
                            guess_leak[2] +=1
                        else:
                            guess_unleak[2] +=1
                    if plaintext[pos] in matches_list:
                        if leak_flag:
                            guess_leak[3] += 1
                        else:
                            guess_unleak[3] += 1

            if leak_num == 0:
                w.write("leak num:" + str(leak_num) + "\n")
                w.write("unleak num:" + str(unleak_num) + "\n")
                w.write("total num:" + str(leak_num + unleak_num) + "\n")
                w.write("q=1:\n") 
                w.write("leak crack:" + str(0) + '\n')
                w.write("unleak crack:" + str(guess_unleak[0]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[0]+guess_unleak[0])/(leak_num+unleak_num)) + '\n')
                w.write("q=10:\n") 
                w.write("leak crack:" + str(0) + '\n')
                w.write("unleak crack:" + str(guess_unleak[1]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[1]+guess_unleak[1])/(leak_num+unleak_num)) + '\n')
                w.write("q=100:\n") 
                w.write("leak crack:" + str(0) + '\n')
                w.write("unleak crack:" + str(guess_unleak[2]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[2]+guess_unleak[2])/(leak_num+unleak_num)) + '\n')
                w.write("q=1000:\n") 
                w.write("leak crack:" + str(0) + '\n')
                w.write("unleak crack:" + str(guess_unleak[3]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[3]+guess_unleak[3])/(leak_num+unleak_num)) + '\n')
            else:
                w.write("leak num:" + str(leak_num) + "\n")
                w.write("unleak num:" + str(unleak_num) + "\n")
                w.write("total num:" + str(leak_num + unleak_num) + "\n")
                w.write("q=1:\n") 
                w.write("leak crack:" + str(guess_leak[0]/leak_num) + '\n')
                w.write("unleak crack:" + str(guess_unleak[0]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[0]+guess_unleak[0])/(leak_num+unleak_num)) + '\n')
                w.write("q=10:\n") 
                w.write("leak crack:" + str(guess_leak[1]/leak_num) + '\n')
                w.write("unleak crack:" + str(guess_unleak[1]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[1]+guess_unleak[1])/(leak_num+unleak_num)) + '\n')
                w.write("q=100:\n") 
                w.write("leak crack:" + str(guess_leak[2]/leak_num) + '\n')
                w.write("unleak crack:" + str(guess_unleak[2]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[2]+guess_unleak[2])/(leak_num+unleak_num)) + '\n')
                w.write("q=1000:\n") 
                w.write("leak crack:" + str(guess_leak[3]/leak_num) + '\n')
                w.write("unleak crack:" + str(guess_unleak[3]/unleak_num) + '\n')
                w.write("total crack:" + str((guess_leak[3]+guess_unleak[3])/(leak_num+unleak_num)) + '\n')

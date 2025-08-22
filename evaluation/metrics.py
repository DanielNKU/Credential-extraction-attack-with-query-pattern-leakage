from datasketch import MinHash, MinHashLSH
from tqdm import tqdm
from collections import defaultdict, Counter

similar_threshold = 0.8

def calculate_successful_identification(frequent_subsequences, plaintext_series):
    success = 0
    lsh = MinHashLSH(threshold=similar_threshold, num_perm=128)
    minhashes = []

    for key, row in tqdm(enumerate(frequent_subsequences), total=len(frequent_subsequences), desc='Loading'):
        m = MinHash(num_perm=128)
        for seq in row:
            m.update(seq.encode('utf8'))
        lsh.insert(key, m)

    for key, query_list in tqdm(enumerate(plaintext_series), total=len(plaintext_series), desc='Calculating successful identification:'):
        m2 = MinHash(num_perm=128)
        for q in query_list:
            m2.update(q.encode('utf8'))
        sim_set = lsh.query(m2)
        if len(sim_set) >= 1:
            success += 1

    return success


def calculate_effective_identification(frequent_subsequences, plaintext_series):
    effectiveness = 0
    lsh = MinHashLSH(threshold=similar_threshold, num_perm=128)

    for key, subseq in tqdm(enumerate(plaintext_series), total=len(plaintext_series), desc='Loading'):
        m = MinHash(num_perm=128)
        for seq in subseq:
            m.update(seq.encode('utf8'))
        lsh.insert(key, m)
    
    for key, query_list in tqdm(enumerate(frequent_subsequences), total=len(frequent_subsequences), desc='Calculating effective identification:'):
        m2 = MinHash(num_perm=128)
        for q in query_list:
            m2.update(q.encode('utf8'))
        sim_set = lsh.query(m2)
        if len(sim_set) >= 1:
            effectiveness += 1

    return effectiveness

def calculate_connected_popular_rate(connected_result, query_type):
    total_p = 0
    popular_p = 0
    top_password = set()
    # You need to set a file for popular passwords
    with open('tgaux_en_toppsw.txt', 'r', encoding='utf-8') as f:
        for line in f:
            pwd, pro = line.split('\t')
            top_password.add(pwd)

    for p in connected_result:
        total_p += len(p[0])
        if query_type == 'pass':
            for pw in p[0]:
                if pw in top_password:
                    popular_p += 1
        elif query_type == 'cred':
            for c in p[0]:
                cre = eval(c)
                if cre[1] in top_password:
                    popular_p += 1

    if total_p == 0:
        return 0, 0, 0
    
    return total_p, popular_p, popular_p / total_p

def calculate_connected_success_rate(connected_result, query_type, origin_path, overlap):
    success = 0
    
    index = defaultdict(set)
    connected_list = []

    output = True
    for key, row in tqdm(enumerate(connected_result), total=len(connected_result), desc='Loading'):
        candidate_list = row[0] + row[2]
        #if output:
            #print(candidate_list)
            #output = False
        connected_list.append(candidate_list)
        for matches in candidate_list:
            index[matches].add(key)

    output = True
    cnt = 0
    with open(origin_path, 'r', encoding='utf8') as f:
        for line in f:
            posp, _, unmatches_list, plaintext = eval(line)
            if len(plaintext) < 10 or _ < 2 or len(plaintext) > 20:
                continue
            cnt += 1
            counter = Counter()
            for unmatches in set(plaintext):
                for idx in index.get(unmatches, []):
                    counter[idx] += 1
            if not counter:
                continue
            best_idx = max(counter, key=lambda x: counter[x])
            if counter[best_idx] >= overlap:
                #if output:
                    #print(connected_list[best_idx])
                    #print(plaintext)
                    #output = False
                success += 1
    print(cnt)
    return success

def calculate_ideal_connected(leak_set_path, query_set_path, origin_path, query_type, overlap):
    leak_table = {}
    leak_set = set()

    index = defaultdict(set)
    connected_list = []
    pos = 0
    with open(leak_set_path, 'r') as f:
        for line in tqdm(f):
            credentials = line.split('\t')[:-1]
            if len(credentials) <= 10:
                continue
            connected_list.append(credentials)
            for c in credentials:
                try:
                    username, password = eval(c)
                except SyntaxError:
                    username, password = eval("['"+c)
                if query_type == "pass":
                    index[password].add(pos)
                elif query_type == "user":
                    index[username].add(pos)
                elif query_type == "cred":
                    index[c].add(pos)
            pos += 1
    
    success = 0
    # output = True
    with open(origin_path, 'r', encoding='utf8') as f:
        for line in tqdm(f):
            posp, _, unmatches_list, plaintext = eval(line)
            if len(plaintext) < 10 or _ < 2 or len(plaintext) > 20:
                continue
            counter = Counter()
            for plain in set(plaintext):
                for idx in index.get(plain, []):
                    counter[idx] += 1
            if not counter:
                continue
            best_idx = max(counter, key=lambda x: counter[x])
            if counter[best_idx] >= overlap:
                #if output:
                    #print(connected_list[best_idx])
                    #print(plaintext)
                    #output = False
                success += 1

    return success

    
# experiments/run_experiment.py

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.query_simulation import split_data, generate_queries
from src.attacks.l_identifying import LIdentifyingAttack
from src.attacks.range_combining import RangeCombiningAttack
from src.attacks.credential_connecting import CredentialConnectingAttack
from src.attacks.credential_guessing import CredentialGuessing
from evaluation.metrics import calculate_successful_identification, calculate_effective_identification, calculate_connected_popular_rate, calculate_connected_success_rate, calculate_ideal_connected 
from tqdm import tqdm
from src.utils import load_plaintext_series, load_config, load_leaked_dataset


def main():
    config = load_config("experiments/configs/config.json")
    
    # # === Step 1: Data Splitting ===
    split_cfg = config["split"]
    split_data(**split_cfg)
    
    # # === Step 2: Query Generation ===
    qgen_cfg = config["query_generation"]
    lengths = qgen_cfg["lengths"]
    qtype = qgen_cfg["query_type"]
    generate_queries(
        leak_file_path=split_cfg["output_leak_path"],
        source_file_path=split_cfg["output_source_path"],
        num_queries=qgen_cfg["num_queries"],
        query_length=lengths,
        query_type=qgen_cfg["query_type"],
        scenario_config=qgen_cfg["scenario_config"],
        output_query_path=os.path.join(config["queries_output_dir"], f"{qtype}_queries_len{lengths}.txt"),
        output_plaintext_path=os.path.join(config["queries_output_dir"], f"{qtype}_plain_queries_len{lengths}.txt")
    )

    # === Step 3: L-identifying + Range Combining ===
    l_idf_cfg = config["identification_attack"]
    length_low = l_idf_cfg["length_low"]
    length_high = l_idf_cfg["length_high"]
    min_threshold = l_idf_cfg["min_threshold"]
    rc = RangeCombiningAttack()
    
    l_identifying_attack_list = []
    for qlen in range(l_idf_cfg["length_low"], l_idf_cfg["length_high"]):
        l_identifying_attack_list.append(LIdentifyingAttack(length_l=qlen, prune_threshold=min_threshold, prune_interval=5000000))
        
    plaintext_series, total_num = load_plaintext_series(os.path.join(config["queries_output_dir"], f"{qtype}_plain_queries_len{lengths}.txt"), l_idf_cfg["length_low"], l_idf_cfg["length_high"]-1, 10)
    
    y_success_graph = [0]
    y_effective_graph = [0]
    with open(os.path.join(config["queries_output_dir"], f"{qtype}_queries_len{lengths}.txt"), 'r') as f:
        cnt = 0
        for line in f:
            cnt += 1
            for id_attack in l_identifying_attack_list:
                id_attack.process(line.strip()) 
            if cnt % 20000000 == 0:
                print("Day", int(cnt/1000000))
                for id_attack in l_identifying_attack_list:
                    rc.load_l_identifying_result(id_attack.get_result(), query_length=id_attack._l)
                identified_results = rc.get_result()
                success_rate = calculate_successful_identification(identified_results, plaintext_series)
                effective_rate = calculate_effective_identification(identified_results, plaintext_series)
                y_success_graph.append(success_rate / total_num)
                y_effective_graph.append(effective_rate / len(identified_results))
                print('Identified numbers:{};Total numbers:{}; Successful identified:{}; Successful rate:{:.2%}; Effective identified:{}; Effective rate: {:.2%}'.format(len(identified_results), total_num, success_rate, success_rate/total_num, effective_rate, effective_rate/len(identified_results)))

    with open(os.path.join(config["identification_output_dir"], f"{qtype}_sequences_len{lengths}_min{min_threshold}_{length_low}-{length_high-1}.txt"), 'w') as g, open(os.path.join(config["identification_output_dir"], f"{qtype}_results_len{lengths}_min{min_threshold}_{length_low}-{length_high-1}.txt"), 'w') as q:
        for seq in rc.get_result():
            g.write(str(seq) + '\n')
        q.write("Success rate:")
        q.write(str(y_success_graph) + '\n')
        q.write("Effective rate:")
        q.write(str(y_effective_graph) + '\n')



    # === Step 4: Credential Connecting ===
    combined = rc.get_result()
    recovery_config = config["recovery_attack"]
    connected_overlap = recovery_config["connect_overlap"]
    identified_queries = []

    with open(os.path.join(config["identification_output_dir"], f"{qtype}_sequences_len{lengths}_min{min_threshold}_{length_low}-{length_high-1}.txt"), 'r') as f:
        for line in tqdm(f, desc="Loading identified queries"):
            identified_queries.append(eval(line))

    connector = CredentialConnectingAttack(split_cfg["output_leak_path"])
    connector.pre_compute(qtype, lengths)
    connected_result = connector.run(identified_queries, connected_overlap)

    total_p, popular_p, popular_rate = calculate_connected_popular_rate(connected_result, qtype)
    success = calculate_connected_success_rate(connected_result, qtype, os.path.join(config["queries_output_dir"], f"{qtype}_plain_queries_len{lengths}.txt"), connected_overlap)
    ideal_succss = calculate_ideal_connected(split_cfg["output_leak_path"], split_cfg["output_source_path"], os.path.join(config["queries_output_dir"], f"{qtype}_plain_queries_len{lengths}.txt"), qtype, connected_overlap)
    if ideal_succss == 0:
        success_rate = 0
    else:
        success_rate = success / ideal_succss
    print('Connected {} pairs; Connected rate: {:.2%}; Total passwords: {}; Popular passwords: {}; Popular rate: {:.2%}; Success numbers: {}; Ideal success: {} Success rate: {:.2%}'.format(len(connected_result), len(connected_result) / len(identified_queries), total_p, popular_p, popular_rate, success, ideal_succss, success_rate))
        
    with open(os.path.join(config["recovery_output_dir"], f"{qtype}_connected_results_len{lengths}_min{connected_overlap}.txt"), 'w', encoding='utf-8') as f:
        f.write('Connected {} pairs; Connected rate: {:.2%}; Total passwords: {}; Popular passwords: {}; Popular rate: {:.2%}; Success numbers: {}; Ideal success: {}; Success rate: {:.2%}'.format(len(connected_result), len(connected_result) / len(identified_queries), total_p, popular_p, popular_rate, success, ideal_succss, success_rate) + '\n')

    with open(os.path.join(config["recovery_output_dir"], f"{qtype}_connected_queries_len{lengths}_min{connected_overlap}.txt"), 'w', encoding='utf-8') as f:
        for r in connected_result:
            f.write(str(r)+'\n')

    # === Step 5: Credential Guessing === 
    CredentialGuessing.extract_old_passwords_from_connected_result(os.path.join(config["recovery_output_dir"], f"{qtype}_connected_queries_len{lengths}_min2.txt"), os.path.join(config["recovery_output_dir"], f"guess_list/{qtype}_old_password_list_len{lengths}.txt"), os.path.join(config["recovery_output_dir"], f"guess_list/{qtype}_old_password_pos_len{lengths}.txt"))
    leak_set = set()
    leak_set = load_leaked_dataset(split_cfg["output_leak_path"], qtype)
    CredentialGuessing.run_guessing_and_match_hashes_rPGM(
        normal_guess_file_path=recovery_config["baseline_path"],
        guess_file_path=os.path.join(config["recovery_output_dir"], f"guess_list/connect_guess.txt"),
        connected_result_path=os.path.join(config["recovery_output_dir"], f"{qtype}_connected_queries_len{lengths}_min{connected_overlap}.txt"),
        origin_path=os.path.join(config["queries_output_dir"], f"{qtype}_plain_queries_len{lengths}.txt"),
        output_path=os.path.join(config["output_guess_result"], f"{qtype}_final_results_len{lengths}_connect.txt"),
        leak_set=leak_set
    )


if __name__ == "__main__":
    main()

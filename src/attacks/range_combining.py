"""
Module: range_combining.py

This module implements the Range Combining Attack as described in our paper's attack model.
It is designed to combine partial outputs (dictionaries of query results) from multiple
L-identifying attacks across different query lengths.

Main class:
    - RangeCombiningAttack

Usage:
    The class accepts input from LIdentifyingAttack via the method `load_l_identifying_result`,
    which takes a list of dictionaries of query counts and a corresponding query length. Internally, it
    merges the new data with previously seen results and tracks the processed lengths.

    At any time, the combined result can be accessed using the `get_result()` method.

Example:
    combiner = RangeCombiningAttack()
    combiner.load_l_identifying_result({"abc": 2, "xyz": 3}, query_length=3)
    combiner.load_l_identifying_result({"abc": 1}, query_length=3)
    result = combiner.get_result()
    print(result)

This module is intended to be used as part of a larger simulation and attack framework.
"""

class RangeCombiningAttack:
    """Combines results from multiple L-identifying attacks across different query lengths.

    This class maintains an internal dictionary of query strings and their aggregated counts 
    from various L-identifying attack results. It also keeps track of which query lengths 
    have been processed to avoid duplicate processing of the same length.
    """

    def __init__(self):
        """Initialize a RangeCombiningAttack with no prior results.

        This sets up an empty combined results dictionary and an empty list of processed query lengths.
        """
        # Internal dictionary to hold combined query counts
        self._combined_results: list = []
        # List to track lengths that have been processed and stored
        self._lengths_processed: list = []

    def load_l_identifying_result(self, result_dict: dict, query_length: int) -> None:
        """Load and combine results from an L-identifying attack for a given query length.

        Merges the provided result dictionary into the internal combined results. If a query string 
        from the result already exists in the combined results, its count is incremented by the new count. 
        This method also records the query length as processed if it hasn't been processed before.

        Args:
            result_dict (dict): A dictionary containing query strings as keys and their occurrence counts as values.
                                 These results are typically produced by an L-identifying attack for a specific length.
            query_length (int): The length of the queries in the provided result_dict.

        Returns:
            None: This method updates the internal state and does not return a value.
        """

        if not self._combined_results:
            self._combined_results.append(result_dict)
            self._lengths_processed.append(query_length)
            return

        # remove the duplicated subsequence
        smaller_pos = -1
        for pos, l in enumerate(self._lengths_processed):
            if l < query_length:
                smaller_pos = pos
                for subseq in result_dict.keys():
                    for i in range(query_length-l):
                        if subseq[i:i+l] in self._combined_results[pos]:
                            self._combined_results[pos].pop(subseq[i:i+l])
            elif l > query_length:
                for subseq in self._combined_results[pos].keys():
                    for i in range(l-query_length):
                        if subseq[i:i+query_length] in result_dict:
                            result_dict.pop(subseq[i:i+query_length])
            elif l == query_length:
                smaller_pos = pos
        # combined the pruned dictionary
        if self._lengths_processed[smaller_pos] < query_length:
            self._lengths_processed.insert(smaller_pos+1, query_length)
            self._combined_results.insert(smaller_pos+1, result_dict)
        elif self._lengths_processed[smaller_pos] == query_length:
            self._combined_results[smaller_pos].update(result_dict)
        else:
            raise ValueError(f"False Value: {l}")

        

    def get_result(self) -> list:
        """Retrieve the combined results of all loaded L-identifying attacks.

        This method returns the internal list of query strings and their aggregated counts. 
        It does not modify the internal state, allowing repeated calls to get the current result.

        Returns:
            list: A list where each key is a query string and the value is the total count 
                  aggregated from all L-identifying results loaded so far.
        """
        result_list = []
        for re_dict in self._combined_results:
            result_list += list(re_dict.keys())
        return result_list


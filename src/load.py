'''
    This provides the logic for loading all of the nvdcve json files into a DataFrame
    NOTE: Uses numpy to save after run, if it finds this file it will reload it
'''

import numpy as np
import pandas as pd
import json

DATA_DIR = 'data/'

def load_kev():
    quick_load = check_existing('kev')
    if quick_load is not None:
        return quick_load

    # Read CSV into a dataframe
    kev_df = pd.read_csv(f'{DATA_DIR}known_exploited_vulnerabilities.csv')
    np.save(f'{DATA_DIR}kev_df.npy', kev_df)
    return kev_df

def load_cve():
    quick_load = check_existing('cve')
    if quick_load is not None:
        return quick_load
    first_fail = True
    # Stores the result from each years json file
    all_years = []
    parse_success_arr_total = [0, 0, 0, 0, 0]
    # the 2025 JSON exists but the data is often incomplete so currently excluded
    for year in range(2002, 2025):

        #print(f'Loading year: {year}')
        # Opens and processes the json file
        all_dicts = []
        parse_success_arr = [0, 0, 0, 0, 0]
        file_name = f'nvdcve-1.1-{year}.json'
        with open(f'{DATA_DIR}{file_name}', "r") as f:
            full_json = json.load(f)
            cve_items = full_json.get("CVE_Items", [])

            for item in cve_items:
                try: 
                    item_dict = {}

                    # Extracting relevant values to a dict
                    item_dict["cveID"] = item["cve"]["CVE_data_meta"]["ID"]

                    cwes_arr = []
                    for problem_type in item["cve"]["problemtype"]["problemtype_data"]:
                        for description in problem_type["description"]:
                            cwes_arr.append(description["value"])
                    item_dict["cwes"] = ";;;".join(cwes_arr)

                    cvss_prefix = "cvss_"
                    impact = item["impact"]

                    # Rejected values have empty impact
                    if not impact:
                        continue
                    elif "baseMetricV2" in impact:
                        log_res = 0
                        baseMetV2 = impact["baseMetricV2"]
                        item_dict["severity"] = baseMetV2["severity"]
                        item_dict["exploitabilityScore"] = baseMetV2["exploitabilityScore"]
                        item_dict["impactScore"] = baseMetV2["impactScore"]
                        # Moved to cvss in v3 and renamed slightly, sometimes doesnt appear, just leave as NaN
                        try:
                            item_dict[f'{cvss_prefix}userInteraction'] = baseMetV2["userInteractionRequired"]
                        except KeyError:
                            pass

                        cvssV2 = baseMetV2["cvssV2"]
                        item_dict[f'{cvss_prefix}version'] = cvssV2["version"]
                        item_dict[f'{cvss_prefix}vectorString'] = cvssV2["vectorString"]
                        # attack=access
                        item_dict[f'{cvss_prefix}attackVector'] = cvssV2["accessVector"]
                        item_dict[f'{cvss_prefix}attackComplexity'] = cvssV2["accessComplexity"]
                        # rough equivalence to v3
                        item_dict[f'{cvss_prefix}privilegesRequired'] = cvssV2["authentication"]
                        item_dict[f'{cvss_prefix}confidentialityImpact'] = cvssV2["confidentialityImpact"]
                        item_dict[f'{cvss_prefix}integrityImpact'] = cvssV2["integrityImpact"]
                        item_dict[f'{cvss_prefix}availabilityImpact'] = cvssV2["availabilityImpact"]
                        item_dict[f'{cvss_prefix}baseScore'] = cvssV2["baseScore"]

                        # Does not exist in v2
                        item_dict[f'{cvss_prefix}scope'] = "DNE:cvssV2"

                        # four metrics got roughly combined into 1, conversion isnt exact
                        if cvssV2["authentication"] == "Au:M" or baseMetV2["obtainAllPrivilege"] or baseMetV2["obtainUserPrivilege"] or baseMetV2["obtainOtherPrivilege"]:
                            translated_pr = "TPR:H"
                        elif cvssV2["authentication"] == "Au:S":
                            translated_pr = "TPR:L"
                        else:
                            translated_pr = "TPR:N"
                        item_dict[f'{cvss_prefix}privilegesRequired'] = translated_pr

                    elif "baseMetricV3" in impact:
                        log_res = 1
                        baseMetV3 = impact["baseMetricV3"]
                        item_dict["exploitabilityScore"] = baseMetV3["exploitabilityScore"]
                        item_dict["impactScore"] = baseMetV3["impactScore"]

                        cvssV3 = baseMetV3["cvssV3"]
                        item_dict[f'{cvss_prefix}version'] = cvssV3["version"]
                        item_dict[f'{cvss_prefix}vectorString'] = cvssV3["vectorString"]
                        item_dict[f'{cvss_prefix}attackVector'] = cvssV3["attackVector"]
                        item_dict[f'{cvss_prefix}attackComplexity'] = cvssV3["attackComplexity"]
                        item_dict[f'{cvss_prefix}privilegesRequired'] = cvssV3["privilegesRequired"]
                        item_dict[f'{cvss_prefix}userInteraction'] = cvssV3["userInteraction"]
                        item_dict[f'{cvss_prefix}scope'] = cvssV3["scope"]
                        item_dict[f'{cvss_prefix}confidentialityImpact'] = cvssV3["confidentialityImpact"]
                        item_dict[f'{cvss_prefix}integrityImpact'] = cvssV3["integrityImpact"]
                        item_dict[f'{cvss_prefix}availabilityImpact'] = cvssV3["availabilityImpact"]
                        item_dict[f'{cvss_prefix}baseScore'] = cvssV3["baseScore"]
                        item_dict["severity"] = cvssV3["baseSeverity"]

                    elif "baseMetricV4" in impact:
                        parse_success_arr[2] += 1
                        #print("Unsupported: Base Metric Version 4")
                        continue
                    else:
                        if first_fail:
                            print(item)
                            first_fail = False
                        parse_success_arr[3] += 1
                        #print("Unsupported: Base Metric Version not recognized")
                        continue
                    
                    item_dict[f'loadSource'] = file_name
                    # Store in all dicts for this year
                    all_dicts.append(item_dict)
                    parse_success_arr[log_res] += 1
                except KeyError as e:
                    parse_success_arr[4] += 1
                    print(f'JSON PARSE ERROR: {e}')
            
        all_years.append(pd.DataFrame(all_dicts))
        print(f'Parse Results Year: {year}\n\tV2: {parse_success_arr[0]}\n\tV3: {parse_success_arr[1]}\n\tV4: {parse_success_arr[2]}\n\tV?: {parse_success_arr[3]}\n\tE: {parse_success_arr[4]}')
        parse_success_arr_total[0] += parse_success_arr[0]
        parse_success_arr_total[1] += parse_success_arr[1]
        parse_success_arr_total[2] += parse_success_arr[2]
        parse_success_arr_total[3] += parse_success_arr[3]
        parse_success_arr_total[4] += parse_success_arr[4]
    print(f'Parse Results Total:\n\tV2: {parse_success_arr_total[0]}\n\tV3: {parse_success_arr_total[1]}\n\tV4: {parse_success_arr_total[2]}\n\tV?: {parse_success_arr_total[3]}\n\tE: {parse_success_arr_total[4]}')

    cve_df = pd.concat(all_years, ignore_index=True)
    np.save(f'{DATA_DIR}cve_df.npy', cve_df)
    return cve_df

def check_existing(source):
    try:
        return pd.DataFrame(np.load(f'{DATA_DIR}{source}_df.npy', allow_pickle=True))
    except FileNotFoundError:
        return None
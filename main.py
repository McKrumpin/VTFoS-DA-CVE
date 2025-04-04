import pandas as pd
import src.load as dfl
import src.helper as h
import json

def main():
    # Load the data
    kev = dfl.load_kev()
    cve = dfl.load_cve()
    comb = dfl.load_comb(kev, cve)

    # Analyze the data
    OUT_DIR = "output/"

    kev_cwe_vc = h.cwe_vc_proc(kev["cwes"].value_counts(), 0)
    kev_cwe_vc.to_csv(f'{OUT_DIR}cwes_counts_KEV.txt', index=True, header=True)

    cve_cwe_vc = h.cwe_vc_proc(cve["cwes"].value_counts(), 1)
    cve_cwe_vc.to_csv(f'{OUT_DIR}cwes_counts_CVE.txt', index=True, header=True)

    kev_cveID_vc = kev["cveID"].value_counts()
    kev_cveID_vc.to_csv(f'{OUT_DIR}cveID_counts_KEV.txt', index=True, header=True)

    kev_target_vc = kev["vendorProject"].value_counts()
    kev_target_vc.to_csv(f'{OUT_DIR}target_counts_KEV.txt', index=True, header=True)

    h.general_analyze(cve, "cve", OUT_DIR)
    h.general_analyze(comb, "comb", OUT_DIR)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error occurred: {e}")
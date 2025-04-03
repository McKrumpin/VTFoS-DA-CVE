import pandas as pd
import src.load as dfl
import src.helper as h
import json

def main():
    # Load the data
    kev = dfl.load_kev()
    cve = dfl.load_cve()

    print (f'KEV shape: {kev.shape}\nCVE shape: {cve.shape}')

    # Analyze the data
    kev_cwe_vc = h.cwe_vc_proc(kev["cwes"].value_counts())
    kev_cwe_vc.to_csv('cwes_counts_KEV.txt', index=True, header=True)

    kev_cveID_vc = kev["cveID"].value_counts()
    kev_cveID_vc.to_csv('cveID_counts_KEV.txt', index=True, header=True)

    kev_target_vc = kev["vendorProject"].value_counts()
    kev_target_vc.to_csv('target_counts_KEV.txt', index=True, header=True)
    
    sevDict = {}
    for cveID in kev['cveID']:
        row = cve[cve['cveID'] == cveID]
        if (row.empty):
            continue
        severity = row['severity'].iloc[0]
        sevDict[severity] = sevDict.get(severity, 0) + 1
    with open('KEV_cveID_sev_vc.txt', 'w') as f:
        json.dump(sevDict, f, indent=2)

    

    # Save / Plot
    #kev_cwes.to_csv("analysis_output/KEV_cwes.csv")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error occurred: {e}")
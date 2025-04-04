# Any helpers for main data analysis
import re

# 0 is not equal, any int > 0 is the number of matches, must have the KEV cwes string as first param
def comp_cwes(cwesStr1, cwesStr2):

    if (not cwesStr1 and not cwesStr2):
        return 0
    
    cwesArr1 = cwesStr1.strip("\"").split(", ")
    cwesArr2 = cwesStr2.split(";;;")
    eCount = 0

    for cwes1 in cwesArr1:
        for cwes2 in cwesArr2:
            if cwes1 == cwes2:
                eCount += 1
                break

    return eCount

# This make a value counts include any multi-CWE properly
def cwe_vc_proc(vcDict, mode):

    procDict = vcDict

    if mode == 0:
        for key, value in procDict.items():
            cwes = key.strip("\"").split(", ")
            if (len(cwes) > 1):
                for cwe in cwes:
                    procDict[cwe] = procDict.get(cwe, 0) + value
                del procDict[key]
    
    if mode == 1:
        for key, value in procDict.items():
            cwes = key.split(";;;")
            if (len(cwes) > 1):
                for cwe in cwes:
                    procDict[cwe] = procDict.get(cwe, 0) + value
                del procDict[key]
    
    return procDict

def general_analyze(df, identifier, OUT_DIR):

    eScore_described = df['exploitabilityScore'].describe()
    eScore_described.to_csv(f'{OUT_DIR}{identifier}_eScore_statistics.txt', index=True, header=True)

    iScore_described = df['impactScore'].describe()
    iScore_described.to_csv(f'{OUT_DIR}{identifier}_iScore_statistics.txt', index=True, header=True)

    baseScore_described = df['cvss_baseScore'].describe()
    baseScore_described.to_csv(f'{OUT_DIR}{identifier}_baseScore_statistics.txt', index=True, header=True)

    sev_vc = df['severity'].value_counts()
    sev_vc.to_csv(f'{OUT_DIR}{identifier}_sev_statistics.txt', index=True, header=True)

    UI_vc = df['cvss_userInteraction'].value_counts()
    UI_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_userInteraction_statistics.txt', index=True, header=True)

    AV_vc = df['cvss_attackVector'].value_counts()
    AV_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_attackVector_statistics.txt', index=True, header=True)

    AC_vc = df['cvss_attackComplexity'].value_counts()
    AC_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_attackComplexity_statistics.txt', index=True, header=True)

    PR_vc = df['cvss_privilegesRequired'].value_counts()
    PR_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_privilegesRequired_statistics.txt', index=True, header=True)

    CI_vc = df['cvss_confidentialityImpact'].value_counts()
    CI_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_confidentialityImpact_statistics.txt', index=True, header=True)

    II_vc = df['cvss_integrityImpact'].value_counts()
    II_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_integrityImpact_statistics.txt', index=True, header=True)

    AI_vc = df['cvss_availabilityImpact'].value_counts()
    AI_vc.to_csv(f'{OUT_DIR}{identifier}_cvss_availabilityImpact_statistics.txt', index=True, header=True)
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
def cwe_vc_proc(vcDict):

    procDict = vcDict
    for key, value in procDict.items():
        cwes = key.strip("\"").split(", ")
        if (len(cwes) > 1):
            for cwe in cwes:
                procDict[cwe] = procDict.get(cwe, 0) + value
            del procDict[key]
    
    return procDict

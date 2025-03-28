# Handles non-standard comparisons in the datasets

# 0 is not equal, any int > 0 is the number of matches
def cwes(cwesStr1, cwesStr2):
    if (not cwesStr1 and not cwesStr2):
        return 0
    
    cwesArr1 = cwesStr1.split(";;;")
    cwesArr2 = cwesStr2.split(";;;")
    eCount = 0

    for cwes1 in cwesArr1:
        for cwes2 in cwesArr2:
            if cwes1 == cwes2:
                eCount += 1
                break

    return eCount


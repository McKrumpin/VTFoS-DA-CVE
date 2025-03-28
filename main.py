import numpy as np
import pandas as pd
import src.load as dfl

def main():
    # Load the data
    kev = dfl.load_kev()
    cve = dfl.load_cve()

    print (f'KEV shape: {kev.shape}\nCVE shape: {cve.shape}')
    # Analyze the data
    # Save / Plot

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error occurred: {e}")
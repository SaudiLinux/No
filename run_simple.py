#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import subprocess

def main():
    print("Starting Auto Security Scanner...")
    print("=" * 50)
    
    # 1. Start Flask server
    print("[1/4] Starting Flask server...")
    subprocess.Popen(['python', 'app.py'], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL)
    time.sleep(5)
    print("Flask server started on http://localhost:5000")
    
    # 2. Run gov test
    print("\n[2/4] Running government sites test...")
    result1 = subprocess.run(['python', 'test_gov.py'], 
                            capture_output=True, text=True)
    if result1.returncode == 0:
        print("✓ Government test completed")
    else:
        print("⚠ Government test completed with warnings")
    
    time.sleep(2)
    
    # 3. Run Google Dorks test
    print("\n[3/4] Running Google Dorks test...")
    result2 = subprocess.run(['python', 'test_gov_dorks.py'], 
                            capture_output=True, text=True)
    if result2.returncode == 0:
        print("✓ Google Dorks test completed")
    else:
        print("⚠ Google Dorks test completed with warnings")
    
    time.sleep(2)
    
    # 4. Run terminal scan
    print("\n[4/4] Running terminal scan...")
    result3 = subprocess.run(['python', 'terminal_scan.py', 'https://www.gov.il'], 
                            capture_output=True, text=True)
    if result3.returncode == 0:
        print("✓ Terminal scan completed")
    else:
        print("⚠ Terminal scan completed with warnings")
    
    print("\n" + "=" * 50)
    print("All scans completed!")
    print("Check the generated JSON files for results")
    print("Flask server is running at http://localhost:5000")

if __name__ == "__main__":
    main()
use this SOC Detector (YARA Scanner):

1. Prerequisites
Before running the script, you need to install the yara-python library:

Bash
pip install yara-python
2. Setup Configuration
In the # --- CONFIGURATION --- section of your code (lines 16-21), ensure the paths match your environment:

WATCH_DIRECTORY: The folder where uploaded files appear (default: ./uploads).

YARA_RULES_FILE: The path to your compiled rules. If you don't have one yet, the script is currently written to fall back to a "TestRule" (lines 28-30) that triggers if the word "malware" is found in a file.

AUTH_LOG_PATH: Ensure your user has permissions to read /var/log/auth.log (usually requires sudo).

3. Execution
Run the script from your terminal:

Bash
python YARA_scanning.py
4. How it Works (The Workflow)
Once started, the script operates in a continuous loop:

Monitor: It watches the WATCH_DIRECTORY for any new files.

Scan: When a file is detected, it runs the YARA engine against it in-memory.

Correlate: If a "hit" occurs (malicious code found), it immediately scans /var/log/auth.log for any failed login attempts that happened within the last 5 minutes.

Alert: It logs the finding, the file path, and the suspicious login telemetry into findings.ndjson.

5. Testing the Scanner
To see if it’s working with the current "TestRule":

Create the upload directory: mkdir uploads

Create a "malicious" test file: echo "this is malware" > ./uploads/test.txt

Check the findings.ndjson file to see the generated alert.

Note: Since this script accesses system logs (/var/log/auth.log), you will likely need to run it with elevated privileges: sudo python YARA_scanning.py.

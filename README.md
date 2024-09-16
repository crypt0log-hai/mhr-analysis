# Automating Malware Hash Registry Analysis

This program is a simple script that automates the process of validating a hash (MD5, SHA1, SHA256) and querying the Malware Hash Registry (MHR) to check if the hash is known to be malicious. It fetches the information from the MHR API and prints the timestamp and AV (Antivirus) hit rate for each malicious hash found into a CSV file.

## Features
- [x] Read hashes from a text file
- [x] Validate hash with regular expression
- [x] Query Malware Hash Registry using DNS API
- [x] Write results to a CSV file
- [x] Debugging mode

## Requirements

### Python 3.x
 
You need to install the following Python libraries:

- dnspython

```bash
pip install -r requirements.txt
```

### Files

- `hashes.txt`: File containing the hashes to be validated
- `main.py`: Script to run the program
- `requirements.txt`: File containing the Python libraries required to run the program

# How it works

1. The script reads the hashes from the `hashes.txt` file.
2. Each hash is validated using a regular expression.
3. Valid hashes are queried using the Malware Hash Registry (MHR) DNS API [https://hash.cymru.com/docs_dns](https://hash.cymru.com/docs_dns) to retrieve the timestamp and AV hit rate of malicious hashes.
4. The results are written to a CSV file named `malicious_hashes.csv`.

Here the project structure and the files used:

```plaintext
.
├── hashes.txt
├── main.py
├── README.md
└── requirements.txt
```

## Usage

1. Set up the `hashes.txt` file with the hashes to be validated. Each hash must be on a separate line.

Example of `hashes.txt` file:

```plaintext
46c6a243281c2590a0e1499412ba4d3eab38e91f,
ae392687023b969d8bd91f4869132c80,
68ff97056ee6cdb74f9c73717c3ed114de271663,
45e163f5e2a6f4d0b9b82653c698952b9e38b776192852445c0f26f02768b8ea
```

2. Run the script `main.py`:

```bash
python main.py
```

3. *Optional*: To enable debug mode, set the `DEBUG` variable to `True` in the `main.py` file.

```python
DEBUG = True
```

4. *Output*: The program will generate a `malicious_hashes.csv` file with the following format:

```plaintext
Hash, AV Hit Rate %, Last Seen
2e9f41ca2846683158cd2e108fe405079910bdd7, 97, 11-05-2016T02:38:12
2e9f41ca2846683158cd2e108fe405079910bdd7, 97, 11-05-2016T02:38:12
2e9f41ca2846683158cd2e108fe405079910bdd7, 97, 11-05-2016T02:38:12
ae392687023b969d8bd91f4869132c80, 97, 11-05-2016T02:38:12
```

## Author

- **Luca Srdjenovic** - 15/09/2024


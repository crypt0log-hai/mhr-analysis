#############################################
#### Malicious Hashes Detection Script
#### Author: Luca Srdjenovic
#### Date: 15.09.2024
#############################################

import re
import dns.resolver
import datetime

# Debugging mode flag
DEBUG_MODE = 0

# Debug print function
def debug_print(message):
    if DEBUG_MODE:
        print("[DEBUG] " + message)

# Validate hash function
def validate_hash(hash):
    md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
    sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

    return md5_pattern.match(hash) or sha1_pattern.match(hash) or sha256_pattern.match(hash)

# Function to query hash.cymru.com for a hash and return the AV rate and timestamp
def query_mhr(hash):
    try:
        name = "hash.cymru.com"
        # If SHA256 hash, split into two parts
        if len(hash) == 64:
            domain = f"{hash[:32]}.{hash[32:]}.{name}"
        else:
            domain = f"{hash}.{name}"

        debug_print(f"Querying domain: {domain}")
        result = dns.resolver.resolve(domain, 'TXT')

        for txt_record in result:
            response = txt_record.to_text().strip('\"')
            debug_print(f"Received response: {response}")

            # The response format must be "TIMESTAMP AV_RATE"
            parts = response.split()

            if len(parts) == 2:
                timestamp, av_rate = parts[0], parts[1]            
                return timestamp, av_rate
            else:
                print(f"Invalid response: {response}")
        
    except dns.resolver.NoAnswer:
        # No TXT records found for the domain
        debug_print(f"No TXT records found for the domain {domain}.")
    except dns.resolver.NXDOMAIN:
        # The domain does not exist
        debug_print(f"The domain {domain} does not exist.")
    except Exception as e:
        debug_print(f"An error occurred: {e}")

    return None, None

# Function to check a list of hashes and return the malicious hashes
def check_hashes(hashes):
    malicious_hashes = []

    for hash in hashes:
        if validate_hash(hash):
            timestamp, av_rate = query_mhr(hash)
            if timestamp and av_rate:
                malicious_hashes.append((hash, av_rate, timestamp))
                debug_print(f"Hash {hash}: {av_rate} - {timestamp}")
            else:
                debug_print(f"Hash {hash}: No valid response from MHR.")
        else:
            debug_print(f"Hash {hash}: Invalid hash format.")

    return malicious_hashes


def main():

    print("==== Starting malicious hashes detection ====")

    print("Reading hashes from hashes.txt file...")

    hashes = []

    # Read hashes from file
    with open('hashes.txt', 'r') as f:
        # Read all lines and strip new line with comma or space
        hashes = [line.strip(',\n') for line in f.readlines()]

    # Get malicious hashes
    malicious_hashes = check_hashes(hashes)

    # Verify is there are malicious hashes
    if len(malicious_hashes) == 0:
        print("==== No malicious hashes found ====")
        return

    # Sort hashes by highest AV rate
    malicious_hashes.sort(key=lambda x: x[1], reverse=True)

    # Write to csv file
    with open('malicious_hashes.csv', 'w') as f:
        f.write("Hash, AV Hit Rate %, Last Seen\n")
        for hash, av_rate, timestamp in malicious_hashes:
            # Convert timestamp to human readable format
            timestamp = datetime.datetime.fromtimestamp(int(timestamp)).strftime('%d-%m-%YT%H:%M:%S')

            debug_print(f"{hash}, {av_rate}, {timestamp}")
            
            f.write(f"{hash}, {av_rate}, {timestamp}\n")


    print("Malicious hashes have been written to malicious_hashes.csv")
    print("==== Malicious hashes detection finished ====")

if __name__ == '__main__':
    main()
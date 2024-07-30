import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import argparse
import nmap

# Load the data for column reference
file_path = 'data.csv'
data = pd.read_csv(file_path, delimiter=';')

data.dropna(inplace=True)
data.drop(columns=['http_response_body', 'path'], inplace=True)
data = pd.get_dummies(data, columns=['product_name', 'version', 'cve_number'])

X = data.drop(columns=['status'])
y = data['status']

# Load the pre-trained model
model = joblib.load('random_forest_model.joblib')

def nmap_scan_and_predict(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV -p 80 --script vulners')

    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                product_name_full = service.get('product', 'unknown')
                product_name = product_name_full.split()[0] if product_name_full and len(product_name_full.split()) > 0 else 'unknown'
                version = service.get('version', 'unknown')
                cve_number = 'unknown'

                if 'script' in service and 'vulners' in service['script']:
                    vulners_output = service['script']['vulners']
                    for line in vulners_output.splitlines():
                        if 'CVE-' in line:
                            cve_number = line.split()[0]
                            break
                scanned_data = pd.DataFrame({
                    'product_name': [product_name],
                    'version': [version],
                    'cve_number': [cve_number]
                })
                scanned_data = pd.get_dummies(scanned_data)
                scanned_data = scanned_data.reindex(columns=X.columns, fill_value=0)
                prediction = model.predict(scanned_data)

                print(f"Port: {port}")
                print(f"Product Name: {product_name}")
                print(f"Version: {version}")
                print(f"CVE Number: {cve_number}")
                print('-' * 40)

                return prediction[0]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('target', type=str, help='Target IP address or hostname to scan')
    args = parser.parse_args()

    status = nmap_scan_and_predict(args.target)
    print("The target status is:", status)
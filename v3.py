import pandas as pd

# Step 1: Load network traffic data from the specified file
def load_traffic_data(file_path):
    data = pd.read_csv(file_path)  # Adjust based on the format of your data
    return data

# Step 2: Extract the leading digit from each traffic value
def extract_leading_digit(traffic_value):
    leading_digit = int(str(traffic_value)[0])
    return leading_digit

# Step 3: Calculate observed frequencies of leading digits in the dataset
def calculate_observed_frequencies(traffic_data):
    observed_freq = [0] * 9
    for value in traffic_data:
        leading_digit = extract_leading_digit(value)
        observed_freq[leading_digit - 1] += 1
    return observed_freq

# Step 4: Generate expected frequencies of leading digits based on Benford's Law
def generate_expected_frequencies():
    expected_freq = [0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046]
    return expected_freq

# Step 5: Compare observed frequencies to expected frequencies and calculate deviations
def calculate_deviations(observed_freq, expected_freq):
    deviations = []
    for i in range(9):
        deviation = observed_freq[i] - expected_freq[i]
        deviations.append(deviation)
    return deviations

# Step 6: Set deviation threshold to determine potential malicious behavior
def set_deviation_threshold():
    deviation_threshold = 5  # Adjust based on your specific scenario
    return deviation_threshold

# Step 7: Generate alerts for traffic values exceeding the deviation threshold
def generate_alerts(traffic_data, deviations, threshold):
    alerts = []
    for i, deviation in enumerate(deviations):
        if abs(deviation) > threshold:
            alert = {
                'Timestamp': traffic_data.iloc[i]['Timestamp'],
                'Traffic Value': traffic_data.iloc[i]['Value'],
                'Deviation': deviation
            }
            alerts.append(alert)
    return alerts

# Step 8: Output the alerts with relevant information
def output_alerts(alerts):
    if len(alerts) > 0:
        print("Malicious Behavior Detected:")
        for alert in alerts:
            print(f"Timestamp: {alert['Timestamp']}, Traffic Value: {alert['Traffic Value']}, Deviation: {alert['Deviation']}")
    else:
        print("No malicious behavior detected.")

# Step 9: Perform further investigation and response actions based on detected malicious behaviors
def perform_investigation(alerts):
    for alert in alerts:
        # Add your investigation and response actions here
        pass

# Main script
def run_insider_threat_detection(file_path):
    # Step 1: Load network traffic data
    traffic_data = load_traffic_data(file_path)
    
    # Step 2: Extract leading digit from each traffic value
    traffic_data['Leading Digit'] = traffic_data['Value'].apply(extract_leading_digit)
    
    # Step 3: Calculate observed frequencies of leading digits
    observed_frequencies = calculate_observed_frequencies(traffic_data['Leading Digit'])
    
    # Step 4: Generate expected frequencies of leading digits based on Benford's Law
    expected_frequencies = generate_expected_frequencies()
    
    # Step 5: Compare observed frequencies to expected frequencies and calculate deviations
    deviations = calculate_deviations(observed_frequencies, expected_frequencies)
    
    # Step 6: Set deviation threshold
    threshold = set_deviation_threshold()
    
    # Step 7: Generate alerts for traffic values exceeding deviation threshold
    alerts = generate_alerts(traffic_data, deviations, threshold)
    
    # Step 8: Output alerts with relevant information
    output_alerts(alerts)
    
    # Step 9: Perform further investigation and response actions
    perform_investigation(alerts)

# Run the script
file_path = "network_traffic_data.csv"  # Update with the path to your network traffic data file
run_insider_threat_detection(file_path)

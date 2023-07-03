import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import chi2

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

# Step 5 (Updated): Compare observed frequencies to expected frequencies and calculate deviations
def calculate_deviations(observed_freq, expected_freq):
    deviations = []
    for i in range(9):
        deviation = observed_freq[i] - expected_freq[i]
        deviations.append(deviation)
    return deviations

# Step 6 (Updated): Set dynamic deviation threshold based on statistical analysis
def set_deviation_threshold(observed_freq):
    chi2_threshold = chi2.ppf(0.95, 8)  # Set the confidence level (e.g., 0.95)
    expected_freq = generate_expected_frequencies()
    variance = sum([(expected_freq[i] * (1 - expected_freq[i])) for i in range(9)])
    threshold = chi2_threshold * np.sqrt(variance / len(observed_freq))
    return threshold

# Step 7 (Updated): Generate alerts for traffic values exceeding the dynamic deviation threshold
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

# Step 8 (Updated): Visualize the observed frequencies, expected frequencies, and deviations
def visualize_results(observed_freq, expected_freq, deviations):
    x = np.arange(1, 10)
    width = 0.35
    
    fig, ax = plt.subplots()
    ax.bar(x - width/2, observed_freq, width, label='Observed Frequencies')
    ax.bar(x + width/2, expected_freq, width, label='Expected Frequencies')
    ax.set_xlabel('Leading Digit')
    ax.set_ylabel('Frequency')
    ax.set_title('Observed vs Expected Frequencies')
    ax.set_xticks(x)
    ax.legend()
    
    fig2, ax2 = plt.subplots()
    ax2.bar(x, deviations)
    ax2.set_xlabel('Leading Digit')
    ax2.set_ylabel('Deviation')
    ax2.set_title('Deviations from Expected Frequencies')
    ax2.set_xticks(x)
    
    plt.show()

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
    
    # Step 6: Set dynamic deviation threshold based on statistical analysis
    threshold = set_deviation_threshold(observed_frequencies)
    
    # Step 7: Generate alerts for traffic values exceeding dynamic deviation threshold
    alerts = generate_alerts(traffic_data, deviations, threshold)
    
    # Step 8: Visualize the observed frequencies, expected frequencies, and deviations
    visualize_results(observed_frequencies, expected_frequencies, deviations)
    
    # Step 9: Perform further investigation and response actions
    perform_investigation(alerts)

# Run the script
file_path = "network_traffic_data.csv"  # Update with the path to your network traffic data file
run_insider_threat_detection(file_path)

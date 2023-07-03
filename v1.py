import pandas as pd
import math
import matplotlib.pyplot as plt

def get_leading_digit(number):
    """Get the leading digit of a number"""
    while number >= 10:
        number //= 10
    return number

def analyze_network_traffic(file_path):
    """Analyze network traffic data using Benford's Law and detect suspicious activity"""
    # Read the network traffic data into a Pandas DataFrame
    df = pd.read_csv(file_path)

    # Extract the relevant column containing traffic values
    traffic_values = df['traffic'].tolist()

    # Count the occurrences of each leading digit in the baseline traffic
    digit_counts_baseline = {digit: 0 for digit in range(1, 10)}
    total_values_baseline = 0

    for value in traffic_values:
        try:
            value = float(value)
            leading_digit = get_leading_digit(value)
            digit_counts_baseline[leading_digit] += 1
            total_values_baseline += 1
        except ValueError:
            pass

    # Calculate the observed frequencies of each leading digit in the baseline traffic
    digit_frequencies_baseline = {digit: count / total_values_baseline for digit, count in digit_counts_baseline.items()}

    # Calculate the expected frequencies based on Benford's Law
    expected_frequencies = {digit: math.log10(1 + 1 / digit) for digit in range(1, 10)}

    # Calculate the threshold for detecting suspicious activity
    threshold = 0.2  # Adjust the threshold based on your requirements

    # Iterate over the subsequent network traffic data for suspicious activity detection
    for i in range(1, len(traffic_values)):
        value = traffic_values[i]

        try:
            value = float(value)
            leading_digit = get_leading_digit(value)

            # Update the counts and frequencies for the current traffic data
            digit_counts = digit_counts_baseline.copy()
            digit_counts[leading_digit] += 1
            total_values = total_values_baseline + 1

            # Calculate the observed frequencies of each leading digit for the current traffic data
            digit_frequencies = {digit: count / total_values for digit, count in digit_counts.items()}

            # Calculate the deviations from the expected frequencies for each leading digit
            deviations = {digit: digit_frequencies[digit] - expected_frequencies[digit] for digit in range(1, 10)}

            # Check if any deviation exceeds the threshold
            if any(abs(deviation) > threshold for deviation in deviations.values()):
                print("[ALERT] Suspicious network activity detected!")
                print(f"Timestamp: {df['timestamp'][i]}")
                print(f"Traffic value: {value}")
                print("Deviation from expected frequencies:")
                for digit, deviation in deviations.items():
                    print(f"Digit {digit}: Deviation = {deviation:.4f}")
                print("--------------------------------------")

        except ValueError:
            pass

if __name__ == "__main__":
    # Specify the file path of the network traffic data
    file_path = "/path/to/network_traffic.csv"

    # Analyze the network traffic and detect suspicious activity using Benford's Law
    analyze_network_traffic(file_path)

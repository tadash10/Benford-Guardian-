# Benford-Guardian-
 insider threat Detection whit python using the Benford Law 

Benford Guardian

Benford Guardian is a Python script that utilizes Benford's Law for insider threat detection in network traffic data. By analyzing the distribution of leading digits in the network traffic, the script identifies anomalies that deviate from the expected pattern, potentially indicating suspicious activity.
How It Works

    Baseline Establishment: The script begins by analyzing a representative sample of normal network traffic data to establish a baseline distribution of leading digits based on Benford's Law.

    Deviation Detection: Subsequent network traffic data is compared to the baseline distribution. Any deviations from the expected frequencies of leading digits are considered anomalies and trigger an alert.

    Threshold Configuration: A deviation threshold is employed to control the sensitivity of the detection. Adjust the threshold value based on the desired balance between detecting potential threats and minimizing false positives.

    Alert Generation: When an anomaly is detected, the script generates an alert providing relevant information such as the timestamp, traffic value, and deviations from the expected frequencies.

Usage

    Install the required dependencies by running pip install pandas matplotlib.

    Prepare your network traffic data in a CSV format with a column containing the traffic values.

    Update the file_path variable in the script with the path to your network traffic data file.

    Adjust the deviation threshold value as needed for your specific environment.

    Run the script using python benford_guardian.py and monitor the console for any generated alerts.

Considerations

    Ensure that the assumptions of Benford's Law hold true for your network traffic data, including a sufficiently large sample size, a wide range of values, and independence among the observed data.

    Regularly update the baseline distribution to adapt to changing network traffic patterns.

    Validate the script's performance on diverse datasets and consider comparing its results with other anomaly detection techniques for comprehensive threat coverage.

    Integrate the script into a broader monitoring and investigation framework to analyze and respond to the detected anomalies effectively.

License

This project is licensed under the MIT License.
Acknowledgments

The script was inspired by the mathematical phenomenon known as Benford's Law and its applications in anomaly detection.

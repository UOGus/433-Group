import matplotlib.pyplot as plt
import numpy as np
import csv

x = []
averages = []
alarms = []
syn_attempts = []  # List for SYN attempts
cusum_results = []  # Add list for CUSUM results

# Read data from CSV
with open(r"C:\Users\Johnt\OneDrive\Documents\GitHub\433-Group\server\attack_detection\data.csv", 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header if there is one
    for row in reader:
        x.append(float(row[0]))  # Time or X axis values
        averages.append(float(row[1]))  # Y values for averages
        alarms.append(int(row[2]))  # Alarms (1 or 0)
        syn_attempts.append(int(row[4]))  # SYN attempts from the new column
        cusum_results.append(float(row[3]))  # Add CUSUM results from the 4th column

# Plotting function for Adaptive Threshold
def plot_adaptive_threshold(x_vals, y_vals, alarms, syn_attempts):
    x_points = np.array(x_vals)
    y_points = np.array(y_vals)
    alarm_points = np.array(alarms)
    syn_points = np.array(syn_attempts)

    # Plotting the averages (or other data)
    plt.plot(x_points, y_points, label='Adaptive Threshold Average', linestyle='-', color='blue')

    # Plotting SYN attempts in a different color
    plt.plot(x_points, syn_points, label='SYN Attempts', linestyle='-', color='green')

    # Highlight points where alarms were triggered
    alarm_indices = np.where(alarm_points == 1)[0]
    plt.scatter(x_points[alarm_indices], y_points[alarm_indices], color='orange', label='Alarm', zorder=3)

    plt.xlabel('Interval')
    plt.ylabel('Traffic Flow')
    plt.title('Adaptive Threshold Traffic Flow Analysis')
    plt.legend()
    plt.show()

# Plotting function for CUSUM Algorithm
def plot_cusum(x_vals, cusum_vals, alarms, syn_attempts):
    x_points = np.array(x_vals)
    cusum_points = np.array(cusum_vals)
    alarm_points = np.array(alarms)
    syn_points = np.array(syn_attempts)

    # Plotting the CUSUM results
    plt.plot(x_points, cusum_points, label='CUSUM', linestyle='-', color='purple')

    # Plotting SYN attempts in a different color
    plt.plot(x_points, syn_points, label='SYN Attempts', linestyle='-', color='green')

    # Highlight points where alarms were triggered
    alarm_indices = np.where(alarm_points == 1)[0]
    plt.scatter(x_points[alarm_indices], cusum_points[alarm_indices], color='orange', label='Alarm', zorder=3)

    plt.xlabel('Interval')
    plt.ylabel('CUSUM Value')
    plt.title('CUSUM Traffic Flow Analysis')
    plt.legend()
    plt.show()

# Call the function to plot Adaptive Threshold with averages, alarms, and SYN attempts
plot_adaptive_threshold(x, averages, alarms, syn_attempts)

# Call the function to plot CUSUM with CUSUM values, alarms, and SYN attempts
plot_cusum(x, cusum_results, alarms, syn_attempts)

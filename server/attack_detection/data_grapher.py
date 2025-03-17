import matplotlib.pyplot as plt
import numpy as np
import csv




x = []
averages = []
alarms = []
syn_attempts = []  # List for SYN attempts
cusum_results = []  # Add list for CUSUM results
adap_alarms = []  # List for Adaptive Threshold alarms
cusum_alarms = []  # List for CUSUM alarms




# Read data from CSV
with open(r"C:\Users\Johnt\OneDrive\Documents\GitHub\433-Group\server\attack_detection\data.csv", 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header if there is one
    for row in reader:
        x.append(float(row[0]))  # Time or X axis values
        averages.append(float(row[1]))  # Y values for averages
        alarms.append(int(row[2]))  # General alarms (1 or 0)
        syn_attempts.append(int(row[5]))  # SYN attempts from the 6th column
        cusum_results.append(float(row[3]))  # CUSUM results from the 4th column
     
        cusum_alarms.append(int(row[4]))  # CUSUM alarms from the 7th column




# Plotting function for Adaptive Threshold
def plot_adaptive_threshold(x_vals, y_vals,alarms, syn_attempts):
    x_points = np.array(x_vals)
    y_points = np.array(y_vals)
    adap_alarm_points = np.array(alarms)
    syn_points = np.array(syn_attempts)




    # Plotting the averages (or other data)
    plt.plot(x_points, y_points, label='Adaptive Threshold Average', linestyle='-', color='blue')




    # Plotting SYN attempts in a different color
    plt.plot(x_points, syn_points, label='SYN Attempts', linestyle='-', color='green')




    # Highlight points where adaptive alarms were triggered
    adap_alarm_indices = np.where(adap_alarm_points == 1)[0]
    plt.scatter(x_points[adap_alarm_indices], y_points[adap_alarm_indices], color='orange', label='Adaptive Alarm', zorder=3)




    plt.xlabel('Interval')
    plt.ylabel('Traffic Flow')
    plt.title('Adaptive Threshold Traffic Flow Analysis')
    plt.legend()
    plt.show()




# Plotting function for CUSUM Algorithm
def plot_cusum(x_vals, cusum_vals, cusum_alarms, syn_attempts):
    x_points = np.array(x_vals)
    cusum_points = np.array(cusum_vals)
    cusum_alarm_points = np.array(cusum_alarms)
    syn_points = np.array(syn_attempts)




    # Plotting the CUSUM results
    plt.plot(x_points, cusum_points, label='CUSUM', linestyle='-', color='purple')




    # Plotting SYN attempts in a different color
    plt.plot(x_points, syn_points, label='SYN Attempts', linestyle='-', color='green')




    # Highlight points where CUSUM alarms were triggered
    cusum_alarm_indices = np.where(cusum_alarm_points == 1)[0]
    plt.scatter(x_points[cusum_alarm_indices], cusum_points[cusum_alarm_indices], color='red', label='CUSUM Alarm', zorder=3)




    plt.xlabel('Interval')
    plt.ylabel('CUSUM Value')
    plt.title('CUSUM Traffic Flow Analysis')
    plt.legend()
    plt.show()




# Call the function to plot Adaptive Threshold with averages, alarms, and SYN attempts
plot_adaptive_threshold(x, averages,alarms, syn_attempts)




# Call the function to plot CUSUM with CUSUM values, alarms, and SYN attempts
plot_cusum(x, cusum_results, cusum_alarms, syn_attempts)











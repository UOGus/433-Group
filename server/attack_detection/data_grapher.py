import matplotlib.pyplot as plt
import numpy as np
import csv

x = []
averages = []
thresholds = []  # You can either fill this in or remove it if not necessary
adaptive_averages = []  # This too is commented out, and can be filled or omitted
alarms = []

# Read data from CSV
with open(r"C:\Users\Johnt\OneDrive\Documents\GitHub\433-Group\server\attack_detection\data.csv", 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header if there is one
    for row in reader:
        x.append(float(row[0]))  # Time or X axis values
        # thresholds.append(float(row[1]))  # Uncomment if you have threshold data
        averages.append(float(row[1]))  # Y values for averages
        # adaptive_averages.append(float(row[3]))  # Uncomment if you have adaptive averages data
        alarms.append(int(row[2]))  # Alarms (1 or 0)


def plot_data(x_vals, y_vals, alarms):
    x_points = np.array(x_vals)
    y_points = np.array(y_vals)
    alarm_points = np.array(alarms)

    # Plotting the averages (or other data)
    plt.plot(x_points, y_points, label='Average', linestyle='-', color='blue')

    # Highlight points where alarms were triggered
    alarm_indices = np.where(alarm_points == 1)[0]
    plt.scatter(x_points[alarm_indices], y_points[alarm_indices], color='orange', label='Alarm', zorder=3)

    plt.xlabel('Interval')
    plt.ylabel('Traffic Flow')
    plt.title('Traffic Flow Analysis')
    plt.legend()
    plt.show()

# Call the function to plot with averages and alarms
plot_data(x, averages, alarms)

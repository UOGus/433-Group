// header file for the adaptive threshold DDoS detection algorithm
struct AdaptiveResult {
    double average;
    int alarm;
};


// run the adaptive threshold algorithm
struct AdaptiveResult adaptive_threshold_algorithm(double past_average, int syn_packets);

// this function checks if the syn traffic in this interval is above the threshold for normal traffic
// if it is above the threshold then raise the alarm 
int adaptive_threshold_check(double past_average, int syn_packets);

// this function computes the estimated weighted moving average (ewma) of the syn packet traffic
// the result of this function will be used to calculate the threshold for normal traffic 
// it should be called after each time interval to update the mean number of syn packets 
double compute_ewma(double past_average, int syn_packets);


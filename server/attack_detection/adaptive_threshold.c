#include <stdio.h>
#include "adaptive_threshold.h"

// percent above mean for normal traffic
// used in alarm condition
// a higher value will raise the threshold for detecting an attack
// a lower value will lower the threshold for detectign a attack
#define alpha 0.5

// weight for estimated weighted moving average
// a larger weight gives more value to recent intervals 
#define beta 0.9




struct AdaptiveResult adaptive_threshold_algorithm(double past_average, int syn_packets){
    struct AdaptiveResult result;
    
    // if average is 0.0 (i.e. first time function is called) set it to a default baseline for traffic
    if(past_average == 0.0){
        result.average = (double)syn_packets;
        result.alarm = 0;
        return result;
        
    }

result.alarm = adaptive_threshold_check(past_average, syn_packets);
    if (result.alarm) {
        printf("ALARM RAISED: Syn flood detected with adaptive threshold algorithm!!\n");
    }

    // return the ewma for this interval so it can be used in the next interval
    result.average = compute_ewma(past_average, syn_packets);
    return result;
}
int adaptive_threshold_check(double past_average, int syn_packets){
    return syn_packets >= (alpha + 1) * past_average;
}

double compute_ewma(double past_average, int syn_packets){
    return (beta * past_average) + ((1-beta) * syn_packets);
}
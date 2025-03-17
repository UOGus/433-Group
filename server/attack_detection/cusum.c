#include "cusum.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

double cusum(double *last_sum, double syn_attempts, double average){
    //expected positive change
    double expected = 20;

    double sum = MAX(0, *last_sum + syn_attempts - average - (average / 2));

    *last_sum = sum;
    return sum;
}
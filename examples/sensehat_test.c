#include <stdio.h>
#include "gyropi.h"

int main(void) {
    int roll, pitch, yaw;
    int retval;
    retval = sensehat_init();

    if (!retval) {
        printf("sensehat_init() failed\n");
    }


    while (1) {
        retval = sensehat_get_gyro(&roll, &pitch, &yaw);
        if (retval == 0) {
            printf("roll : %03d - pitch : %03d - yaw : %03d\n", roll + 180, pitch + 180, yaw + 180);
        }
    }
    return 0;
}

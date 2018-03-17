#ifdef HAVE_RTIMULIB_H
#include "RTIMULib.h"

static RTIMUSettings *settings;
static RTIMU *imu;

extern "C" int sensehat_init(void) {
    settings = new RTIMUSettings("RTIMULib");
    imu = RTIMU::createIMU(settings);

    if ((imu == NULL) || (imu->IMUType() == RTIMU_TYPE_NULL)) {
        fprintf(stderr, "No IMU found\n");
        return -1;
    }

    //  This is an opportunity to manually override any settings before the call IMUInit
    //  set up IMU
    imu->IMUInit();

    //  this is a convenient place to change fusion parameters
    imu->setSlerpPower(0.02);
    imu->setGyroEnable(true);
    imu->setAccelEnable(false);
    imu->setCompassEnable(false);

    return 0;
}

extern "C" int sensehat_get_gyro(int *roll, int *pitch, int *yaw ) {
    RTIMU_DATA imuData;

    if (!imu->IMURead()) {
        return -1;
    }

    imuData = imu->getIMUData();

    if (roll) {
        *roll = (int) (RTMATH_RAD_TO_DEGREE * imuData.fusionPose.x());
    }

    if (pitch) {
        *pitch = (int) (RTMATH_RAD_TO_DEGREE * imuData.fusionPose.y());
    }

    if (yaw) {
        *yaw = (int) (RTMATH_RAD_TO_DEGREE * imuData.fusionPose.z());
    }

    return 0;
}
#else

extern "C" int sensehat_init(void) {
    return 0;
}

extern "C" int sensehat_get_gyro(int *roll, int *pitch, int *yaw) {
    if (roll) {
        *roll = 1;
    }

    if (pitch) {
        *pitch = 2;
    }

    if (yaw) {
        *yaw = 3;
    }
    return 0;
}

#endif

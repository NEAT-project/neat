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
    imu->setAccelEnable(true);
    imu->setCompassEnable(true);

    return 0;
}

extern "C" int sensehat_get_gyro(float *x, float *y, float *z) {
    RTIMU_DATA imuData;

    if (!imu->IMURead()) {
        return -1;
    }

    imuData = imu->getIMUData();
    fprintf(stderr, "Sample %s\n", RTMath::displayDegrees("", imuData.fusionPose));
    if (x) {
        *x = RTMATH_RAD_TO_DEGREE * imuData.fusionPose.x();
    }
    
    if (y) { 
        *y = RTMATH_RAD_TO_DEGREE * imuData.fusionPose.y();
    }

    if (z) {
        *z = RTMATH_RAD_TO_DEGREE * imuData.fusionPose.z();
    }
 
    return 0;
}
#else

extern "C" int sensehat_init(void) {
    return 0;
}

extern "C" int sensehat_get_gyro(float &x, float &y, float &z) {
    return 0;
}

#endif

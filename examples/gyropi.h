#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC int sensehat_init(void);
EXTERNC int sensehat_get_gyro(int *roll, int *pitch, int *yaw);

#undef EXTERNC

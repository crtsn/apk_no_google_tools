#include <jni.h>
#include <dlfcn.h>

JNIEXPORT jstring JNICALL
Java_com_example_test_MainActivity_getHelloString(JNIEnv *env, jobject obj) {
	char *result = "libc.so NOT OPENED";

	void *handle = dlopen("libc.so", RTLD_LAZY);
	if (handle) {
		result = "libc.so OPENED!!!";
    }
	return (*env)->NewStringUTF(env, result);
}

#include <jni.h>
#include <dlfcn.h>

JNIEXPORT jstring JNICALL
Java_com_example_test_MainActivity_getHelloString(JNIEnv *env, jobject obj) {
	char buf[128] = "libc.so NOT LOADED :Sadge:";

	void *handle = dlopen("libc.so", RTLD_LAZY);
	if (handle) {
		char *(*strncat)(char *dst, char src[], size_t ssize) = dlsym(handle, "strncat");
		strncat(buf, "SIKE! :POG:", 128);
    }
	return (*env)->NewStringUTF(env, buf);
}

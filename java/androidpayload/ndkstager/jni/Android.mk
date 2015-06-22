LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := ndkstager
LOCAL_SRC_FILES := ndkstager.c

include $(BUILD_SHARED_LIBRARY)

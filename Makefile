export ARCHS = arm64

export DEBUG = 1
export FINALPACKAGE = 0

export PREFIX = $(THEOS)/toolchain/Xcode11.xctoolchain/usr/bin/

export TARGET := iphone:clang:14.5:7.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MGSpoof
MGSpoof_FILES = Tweak.xm mapping.mm
MGSpoof_CFLAGS = -fobjc-arc
MGSpoof_LDFLAGS = -lz -L. -v -force_load ./libcapstone.a
MGSpoof_LIBRARIES = MobileGestalt
MGSpoof_EXTRA_FRAMEWORKS = Cephei

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
SUBPROJECTS += mgspoofhelper
include $(THEOS_MAKE_PATH)/aggregate.mk

QT += core dbus network
CONFIG += c++14
TARGET = YUNA
TEMPLATE = app

SOURCES += YUNA.cpp

HEADERS += firewallInterface.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# Ensure proper build environment
CONFIG += console
CONFIG -= app_bundle

# Add this line to ensure proper MOC processing
CONFIG += no_keywords

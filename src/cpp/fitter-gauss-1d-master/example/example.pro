QT += core
QT += gui

greaterThan(QT_MAJOR_VERSION,4): QT += widgets printsupport

CONFIG += c++11

TARGET = gauss1fit
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    mainwindow.cpp \
    qcustomplot.cpp

HEADERS += \
    mainwindow.h \
    qcustomplot.h

GSLROOTDIR=$$(HOME)/Software/gsl-2.1

INCLUDEPATH += $${GSLROOTDIR}/include
LIBS += -L$$GSLROOTDIR/lib -lgsl

FORMS += \
    mainwindow.ui

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../lib/release/ -lfitter-gauss-1d
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../lib/debug/ -lfitter-gauss-1d
else:unix: LIBS += -L$$OUT_PWD/../lib/ -lfitter-gauss-1d

INCLUDEPATH += $$PWD/../lib
DEPENDPATH += $$PWD/../lib

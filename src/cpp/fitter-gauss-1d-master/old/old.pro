QT += core
QT += gui

greaterThan(QT_MAJOR_VERSION,4): QT += widgets printsupport

CONFIG += c++11

TARGET = gauss1fit
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    Gaussian1dFitService.cpp \
    Gauss1d.cpp \
    PolynomialFitter1D.cpp \
    LevMar.cpp \
    mainwindow.cpp \
    qcustomplot.cpp

HEADERS += \
    Gaussian1dFitService.h \
    Gauss1d.h \
    HeuristicGauss1dFitter.h \
    PolynomialFitter1D.h \
    LBTAGauss1dFitter.h \
    LMGaussFitter1d.h \
    LevMar.h \
    main.h \
    mainwindow.h \
    qcustomplot.h

GSLROOTDIR=$$(HOME)/Software/gsl-2.1

INCLUDEPATH += $${GSLROOTDIR}/include
LIBS += -L$$GSLROOTDIR/lib -lgsl

FORMS += \
    mainwindow.ui


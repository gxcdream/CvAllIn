QT += core
QT += gui

greaterThan(QT_MAJOR_VERSION,4): QT += widgets printsupport

CONFIG += c++11

TARGET = fitter-gauss-1d
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = lib

#CONFIG += shared_and_static build_all
CONFIG += staticlib

SOURCES += \
    Gaussian1dFitService.cpp \
    Gauss1d.cpp \
    PolynomialFitter1D.cpp \
    LevMar.cpp

HEADERS += \
    Gaussian1dFitService.h \
    Gauss1d.h \
    HeuristicGauss1dFitter.h \
    PolynomialFitter1D.h \
    LBTAGauss1dFitter.h \
    LMGaussFitter1d.h \
    LevMar.h

GSLROOTDIR=$$(HOME)/Software/gsl-2.1

INCLUDEPATH += $${GSLROOTDIR}/include
LIBS += -L$$GSLROOTDIR/lib -lgsl

FORMS += \
    mainwindow.ui



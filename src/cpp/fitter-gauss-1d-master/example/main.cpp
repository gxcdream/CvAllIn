#include "Gaussian1dFitService.h"
#include "mainwindow.h"

#include <QApplication>
#include <QDebug>

int
main( int argc, char * argv[] )
{
    QApplication a( argc, argv );
    MainWindow mw;
    mw.show();

    return a.exec();
} // main

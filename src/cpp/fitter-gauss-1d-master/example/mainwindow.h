#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "Gaussian1dFitService.h"

#include <QMainWindow>

namespace Ui
{
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:

    explicit
    MainWindow( QWidget * parent = 0 );
    ~MainWindow();

//    void qMessageHandler(QtMsgType type, const QMessageLogContext & ctx, const QString & txt);


private slots:

    void
    on_actionQuit_triggered();


    void
    onSliderChanged();
    void
    submitRequest();

    void gfResultsCB( Gaussian1dFitService::ResultsG1dFit);

    void regenButtonCB();


private:

    Ui::MainWindow * ui = nullptr;
    Gaussian1dFitService::Manager * m_gfm = nullptr;
    Gaussian1dFitService::InputParametersG1dFit m_gfInput;
    Gaussian1dFitService::ResultsG1dFit m_gfResult;
    qint64 m_lastGfId = 0;
};

#endif // MAINWINDOW_H

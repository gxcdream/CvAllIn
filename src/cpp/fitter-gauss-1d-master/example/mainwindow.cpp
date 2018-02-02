#include "mainwindow.h"
#include "ui_mainwindow.h"

typedef std::vector < double > VD;
typedef QVector < double > QVD;

static double
fact( int i )
{
    if ( i < 2 ) {
        return 1;
    }
    else {
        return double (i) * fact( i - 1 );
    }
}

static
VD
makeData( int n, int nGauss, int poly, double rnd )
{
    VD params;
    for ( int i = 0 ; i < nGauss ; ++i ) {
        Optimization::Gauss1dNiceParams nice;

        // 1: 1/2
        // 2: 1/3 2/3
        // 3: 1/4 2/4 3/4
        double w = double (n) / ( nGauss + 1.0 );
        nice.center = ( i + 1 ) * w;
        nice.amplitude = 2 - drand48() * rnd;
        nice.fwhm = w * 0.3;
        nice.center += ( drand48() - 0.5 ) * rnd * nice.fwhm;
        nice.amplitude += ( drand48() - 0.5 ) * rnd;
        nice.fwhm += ( drand48() - 0.5 ) * rnd * w * 0.1;

//        center = n/2; ampl = 10; var = -1;
        auto ugly = nice.convertToUgly();
        params.push_back( ugly[0] );
        params.push_back( ugly[1] );
        params.push_back( ugly[2] );
    }
    for ( int i = 0 ; i < poly ; ++i ) {
        if( i % 2 == 1) {
            double ii = (i-1) / 2;
            params.push_back( pow(-1.0,ii) / fact(2*ii+1) / pow(n/8,2*ii+1));
        } else {
            int ii = i / 2;
            params.push_back( pow(-1.0,ii) / fact(2*ii) / pow(n/8,2*ii));
        }
    }

    VD result( n );
    for ( int i = 0 ; i < n ; ++i ) {
        result[i] = Optimization::evalNGauss1dBkg( i, nGauss, poly, params );
        result[i] += ( drand48() - 0.5 ) * rnd;
    }

    return result;

//    VD result( n );
//    auto fn = [&] ( double x ) {
//                  return ( drand48() - 0.5 ) * rnd * 2;
//              };

//    for ( int i = 0 ; i < n ; ++i ) {
//        double x = double (i) / ( n - 1 );
//        result[i] = fn( x );
//    }

//    return result;
} // makeData

MainWindow::MainWindow( QWidget * parent ) :
    QMainWindow( parent ),
    ui( new Ui::MainWindow )
{
    ui->setupUi( this );
    connect( ui->regenInputButton, & QPushButton::clicked,
             this, & MainWindow::regenButtonCB );

    ui->customPlot->addGraph();
    ui->customPlot->addGraph();
    QVector < double > x = {
        0, 0.5, 0.9
    };
    QVector < double > y = {
        0.5, 0.9, 0.1
    };
    ui->customPlot->graph( 1 )->setPen( QPen( QBrush( QColor( 255, 0, 0, 64 ) ), 5 ) );

    ui->customPlot->setInteractions(
        QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables
        | QCP::iSelectAxes );

    ui->sliderDataSize->setValue( 100 );
    ui->sliderGauss->setValue( 1 );
    ui->sliderPoly->setValue( 0 );
    ui->sliderNoise->setValue( 0.2 * ui->sliderNoise->maximum() );

    connect( ui->sliderDataSize, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );
    connect( ui->sliderGauss, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );
    connect( ui->sliderPoly, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );
    connect( ui->sliderNoise, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );
    connect( ui->sliderGauss2, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );
    connect( ui->sliderPoly2, & QSlider::valueChanged, this, & MainWindow::onSliderChanged );

    connect( ui->sliderGauss2, & QSlider::valueChanged, this, & MainWindow::submitRequest );
    connect( ui->sliderPoly2, & QSlider::valueChanged, this, & MainWindow::submitRequest );
    connect( ui->checkBoxRH, & QCheckBox::toggled, this, & MainWindow::submitRequest );

    // create a gaussian fit manager
    m_gfm = new Gaussian1dFitService::Manager( this );
    connect( m_gfm, & Gaussian1dFitService::Manager::results,
             this, & MainWindow::gfResultsCB );

    onSliderChanged();
    regenButtonCB();
}

MainWindow::~MainWindow()
{
    delete ui;
}

//void MainWindow::qMessageHandler(QtMsgType type, const QMessageLogContext &ctx, const QString &txt)
//{
//    QString types;
//    switch (type) {
//    case QtDebugMsg: types = "D"; break;
//    case QtWarningMsg: types = "W"; break;
//    case QtCriticalMsg: types = "C"; break;
//    case QtFatalMsg: types = "F"; break;
//    case QtInfoMsg: types = "I"; break;
//    default:
//        types="U";
//    }
//    ui->outputText->append( QString("%1:%2").arg(types).arg(txt));
//}

void
MainWindow::on_actionQuit_triggered()
{
    QApplication::exit();
}

void
MainWindow::regenButtonCB()
{
    auto dataSize = ui->sliderDataSize->value();
    auto nGauss = ui->sliderGauss->value();
    auto nPoly = ui->sliderPoly->value();
    double noise = ui->sliderNoise->value() / double ( ui->sliderNoise->maximum() );

    m_gfInput.data = makeData( dataSize, nGauss, nPoly, noise );
    m_gfInput.isNull = false;
    m_lastGfId++;
    m_gfInput.stamp = m_lastGfId;
    m_gfInput.left = 0;
    m_gfInput.right = m_gfInput.data.size() - 1;
    m_gfInput.randomHeuristicsEnabled = true;

    // update plot with the input data
    QVector < double > vx( m_gfInput.data.size() );

//    auto vy = vx;
    QVector < double > vy( m_gfInput.data.size() );
    for ( size_t i = 0 ; i < m_gfInput.data.size() ; ++i ) {
        vx[i] = i;
        vy[i] = m_gfInput.data[i];
    }

    ui->customPlot->graph( 0 )-> setData( vx, vy );
    ui->customPlot->rescaleAxes();
    ui->customPlot->replot();

    submitRequest();
} // MainWindow::regenButtonCB

void
MainWindow::onSliderChanged()
{
    ui->labelDataSize->setNum( ui->sliderDataSize->value() );
    ui->labelGauss->setNum( ui->sliderGauss->value() );
    ui->labelPoly->setNum( ui->sliderPoly->value() );
    ui->labelNoise->setNum( ui->sliderNoise->value() );

    ui->labelGauss2->setNum( ui->sliderGauss2->value() );
    ui->labelPoly2->setNum( ui->sliderPoly2->value() );
}

void
MainWindow::submitRequest()
{
    m_gfInput.nGaussians = ui->sliderGauss2->value();
    m_gfInput.poly = ui->sliderPoly2->value();
    m_gfInput.randomHeuristicsEnabled = ui->checkBoxRH->isChecked();
    m_gfm->request( m_gfInput );
} // MainWindow::onSliderChanged

void
MainWindow::gfResultsCB( Gaussian1dFitService::ResultsG1dFit res )
{
    m_gfResult = res;
    qDebug() << "results:" << m_gfResult.toString();

    QString status;
    if ( m_gfResult.status() == m_gfResult.Complete ) {
        status = "Complete";
    }
    else if ( m_gfResult.status() == m_gfResult.Partial ) {
        status = "Partial";
    }
    else {
        status = "Error";
    }
    ui->statusbar->showMessage( QString( "%1 %2" ).arg( status ).arg( m_gfResult.toString() ) );

    // replot the result
    int inputSize = m_gfInput.data.size();
    int outputSize = inputSize * 2;
    QVD vx( outputSize ), vy( outputSize );
    for ( int i = 0 ; i < outputSize ; ++i ) {
        double x = double (i) / outputSize * inputSize;
        double y = Optimization::evalNGauss1dBkg(
            x,
            m_gfResult.input.nGaussians,
            m_gfResult.input.poly,
            m_gfResult.params );
        vx[i] = x;
        vy[i] = y;
    }
    ui->customPlot->graph( 1 )->setData( vx, vy );
    ui->customPlot->replot();
} // MainWindow::gfResultsCB

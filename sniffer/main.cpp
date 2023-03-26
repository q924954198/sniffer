#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QtDebug>
#include <QApplication>
#include <QLocale>
#include <QComboBox>
#include <QTranslator>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <time.h>
#include <typeinfo>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <qthread.h>

using namespace std;




int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "sniffer_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }
    MainWindow w;
    w.show();



    return a.exec();
}

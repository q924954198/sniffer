#include "mainwindow.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

using namespace std;

int pcap_analyse(){
    char buf[100];
    pcap_if_t *alldev;
    pcap_findalldevs(&alldev,buf);
    for(pcap_if_t *pdev=alldev;pdev;pdev=pdev->next){
        printf("%s\n",pdev->name);
    }
    return 0;
}

/*int pcap_analyse()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    printf("Device %s\n", dev);
    return(0);
}*/

int main(int argc, char *argv[])
{
    pcap_analyse();
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

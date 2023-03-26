#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap/pcap.h"
#include "MyThread.h"
class MyThread;
//typedef void(*pcap_handler)(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet);

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    Ui::MainWindow *ui;
    static MainWindow *wid;
private slots:
    void on_start_stop_clicked();
    void on_promiscuous_mode_stateChanged();

private:
    MyThread *mythread;
public:

    void Sniffer();

    static void PacketCallback(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet);

};



#endif // MAINWINDOW_H

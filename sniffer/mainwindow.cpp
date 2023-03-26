#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "MyThread.h"

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
#include <linux/udp.h>
#include <qthread.h>
#include <QQueue>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define MAXSIZE 100000;

int dev_index;
char *dev[100];
int promismode;
char ebuf[100];
char net_ebuf[100];
pcap_t *p_open;
int flowTotal;
u_int id =0;
char filter[128];

struct timeval start_time_v;
struct timezone start_time_z;


QQueue<const u_char*> packet_data;
QQueue<const struct pcap_pkthdr *> packet_header;

MainWindow *MainWindow::wid = nullptr;


MyThread::MyThread(){

}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    wid=this;
    mythread = new MyThread;
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setColumnWidth(0,40);
    ui->tableWidget->setColumnWidth(1,100);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    ui->tableWidget->setColumnWidth(4,80);
    ui->tableWidget->setColumnWidth(5,40);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

    /*搜寻本机所有可用网卡并放置在ui的interface_choose选项栏中*/
    char buf[100];
    pcap_if_t *alldev;
    pcap_findalldevs(&alldev,buf);
    int i=0;
    for(pcap_if_t *pdev=alldev;pdev;pdev=pdev->next){
        ui->interface_choose->addItem(pdev->name);
        dev[i]=pdev->name;
        i++;
    }
    connect(ui->interface_choose,static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),this,[&](int index){
        dev_index=ui->interface_choose->currentIndex();
        /*通过interface_choose是否被选择判断button是否应该亮起*/
        if(dev[dev_index]==nullptr){
            ui->start_stop->setEnabled(false);
        }
        else{
            ui->start_stop->setEnabled(true);
        }
        qDebug("%d",dev_index);
        /*获取interface_choose当前索引内容，并转化至char*/
    });
    //connect(mythread,&MyThread::toData,this,&MainWindow::packetget);
    /*打开网络接口并监听,同时切换button名称*/
    /*struct bpf_program bp;
    if(!ui->filter_write->text().isEmpty()){
        strcpy(filter,ui->filter_write->text().toStdString().data());
        if(pcap_compile(p_open,&bp,filter,0,))
    }*/

}


/*网络接口获取*/
void MainWindow::Sniffer(){


}

/*混杂模式*/
void MainWindow::on_promiscuous_mode_stateChanged()
{

    /*判断混杂模式是否被选中 */

    if(ui->promiscuous_mode->isChecked()==true){
        promismode = 1;
    }
    else{
        promismode = 0;
    }

    qDebug("%d",promismode);
}


/*回调函数*/
void MainWindow::PacketCallback(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet){

    int *id = (int *)user;

    struct in_addr addr;
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    struct ether_header *eptr;
    u_char *ptr;
    char *data;
    int i;
    //packet_data.enqueue(packet);
    //packet_header.enqueue(pkthdr);
    int row = wid->ui->tableWidget->rowCount();
    wid->ui->tableWidget->insertRow(row);
    wid->ui->tableWidget->setItem(row,0,new QTableWidgetItem(QString("%1").arg(row+1)));
    double dif = (pkthdr->ts.tv_sec-start_time_v.tv_sec+pkthdr->ts.tv_usec/1000000.0-start_time_v.tv_usec/1000000.0);
    //qDebug("%lf",dif);
    eptr = (struct ether_header*)packet;
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    /*printf("%d\n",i);
    printf("Dest is:");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN)?"":":",*ptr++);
    }while(--i>0);
    printf("\n");*/
    /*IP*/
    if(ntohs(eptr->ether_type)==ETHERTYPE_IP){
        /*ip header*/
        ipptr = (struct iphdr*)(packet+sizeof (struct ether_header));
        addr.s_addr = ipptr->daddr;
        wid->ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString::fromStdString(inet_ntoa(addr))));
        addr.s_addr = ipptr->saddr;
        wid->ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString::fromStdString(inet_ntoa(addr))));

        /*ICMP*/
        if(ipptr->protocol==1){
            wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("ICMP"));
        }
        /*IGMP*/
        else if(ipptr->protocol==2){
            wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("IGMP"));
        }

        /*TCP*/
        else if(ipptr->protocol==6){
            tcpptr=(struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof (struct iphdr));
            if(ntohs(tcpptr->dest)==21||ntohs(tcpptr->source)==21){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("FTP"));
            }
            else if(ntohs(tcpptr->dest)==23||ntohs(tcpptr->source)==23){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("TTS"));
            }
            else if(ntohs(tcpptr->dest)==80||ntohs(tcpptr->source)==80){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("HTTP"));
            }
            else if(ntohs(tcpptr->dest)==25||ntohs(tcpptr->source)==25){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("SMTP"));
            }
            else if(ntohs(tcpptr->dest)==110||ntohs(tcpptr->source)==110){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("POP3"));
            }
            else if(ntohs(tcpptr->dest)==443||ntohs(tcpptr->source)==443){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("HTTPS"));
            }
            else{
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("TCP"));
            }
            wid->ui->tableWidget->setItem(row,7,new QTableWidgetItem(QString("%6").arg(ntohs(tcpptr->dest))));
            wid->ui->tableWidget->setItem(row,6,new QTableWidgetItem(QString("%6").arg(ntohs(tcpptr->source))));
        }

        /*UDP*/
        else if(ipptr->protocol==17){
            udpptr=(struct udphdr*)(packet+sizeof(struct ether_header)+sizeof (struct iphdr));
            if(ntohs(udpptr->dest)==53||ntohs(udpptr->source)==53){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("DNS"));
            }
            else if(ntohs(udpptr->dest)==69||ntohs(udpptr->source)==69){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("TFTP"));
            }
            else if(ntohs(udpptr->dest)==161||ntohs(udpptr->source)==161){
                wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("SNMP"));
            }
            else{
            wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("UDP"));
            }
            wid->ui->tableWidget->setItem(row,7,new QTableWidgetItem(QString("%6").arg(ntohs(udpptr->dest))));
            wid->ui->tableWidget->setItem(row,6,new QTableWidgetItem(QString("%6").arg(ntohs(udpptr->source))));
        }
    }
    /*ARP*/
    else if(ntohs(eptr->ether_type)==ETHERTYPE_ARP){
        wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("ARP"));
    }
    /*IPV6*/
    else if(ntohs(eptr->ether_type)==ETHERTYPE_IPV6){
        wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem("IPV6"));
    }

    else{
        wid->ui->tableWidget->setItem(row,4,new QTableWidgetItem(""));
    }

    wid->ui->tableWidget->setItem(row,1,new QTableWidgetItem(QString("%6").arg(dif)));

    wid->ui->tableWidget->setItem(row,5,new QTableWidgetItem(QString("%6").arg(pkthdr->len)));

    id++;
}

/**/


/*按钮切换状态*/
void MainWindow::on_start_stop_clicked()
{
    if(ui->start_stop->text()=="开始捕获"){
        bpf_u_int32 net;
        bpf_u_int32 mask;
        p_open = pcap_open_live(dev[dev_index],BUFSIZ,promismode,0,ebuf);
        if(p_open){
            if(pcap_lookupnet(dev[dev_index],&net,&mask,net_ebuf)==-1){
                net = 0;
                mask = 0;
            }
            struct bpf_program bp;
            if(!ui->filter_write->text().isEmpty()){
                strcpy(filter,ui->filter_write->text().toStdString().data());
                if(pcap_compile(p_open,&bp,filter,0,net)==-1){
                    ui->filter_write->setStyleSheet("background:red");
                    return;
                }
                if(pcap_setfilter(p_open,&bp)==-1){
                    ui->filter_write->setStyleSheet("background:red");
                    return;;
                }
                else{
                    ui->filter_write->setStyleSheet("background:green");
                }
            }
            packet_data.clear();
            packet_header.clear();
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            ui->start_stop->setText("停止捕获");
            ui->interface_choose->setEnabled(false);
            ui->promiscuous_mode->setEnabled(false);
            ui->filter_write->setEnabled(false);
            mythread->start();
            qDebug("open is ok");
        }
        else{
            qDebug("%s",ebuf);
            qDebug("open is error");
        }
    }
    else{
        ui->start_stop->setText("开始捕获");
        //printf("%u",packet_arr[2]);
        ui->interface_choose->setEnabled(true);
        ui->promiscuous_mode->setEnabled(true);
        ui->filter_write->setEnabled(true);
        pcap_breakloop(p_open);
        pcap_close(p_open);
    }
    qDebug("push");
}

/*main packet get*/
//void mai

/*run*/
void MyThread::run(){
    int *id=0;
    gettimeofday(&start_time_v,&start_time_z);
    qDebug("%ld",start_time_v.tv_sec);
    qDebug("%ld",start_time_v.tv_usec);
    pcap_loop(p_open,-1,MainWindow::PacketCallback,(u_char *)&id);
    //emit toData();
    qDebug("run is ok");
}

/**/



MainWindow::~MainWindow()
{
    delete ui;
}









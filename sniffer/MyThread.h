#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QThread>
#include "mainwindow.h"
#include "ui_mainwindow.h"

class MainWindow;
class MyThread : public QThread{
    Q_OBJECT;
public:
    MyThread();
protected:
    void run() override;
signals:
    void toData();
public:

    explicit MyThread(Ui::MainWindow *p);
    Ui::MainWindow* exUI;

    //static MyThread *wid;

};

#endif // MYTHREAD_H

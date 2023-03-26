#ifndef UI_INVOKE_H
#define UI_INVOKE_H

#include <QObject>
#include "mainwindow.h"
#include "ui_mainwindow.h"

class MainWindow;

class ui_invoke:public QObject{
    Q_OBJECT
public:
    explicit ui_invoke(Ui::MainWindow *p);
    Ui::MainWindow* exUI;

signals:

};

#endif // UI_INVOKE_H

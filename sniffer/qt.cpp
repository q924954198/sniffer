#include<qapplication.h>
#include<qlabel.h>

int main(int argc,char *argv[]){
	QApplication app(argc,argv);
	QLabel*label=new QLabel("hello QT",0);
	label->show();
	return app.exec();
}

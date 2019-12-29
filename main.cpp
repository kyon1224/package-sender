#include "QtGuiApplication5.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QtGuiApplication5 w;
	w.show();
	return a.exec();
}

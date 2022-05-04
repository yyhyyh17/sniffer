#include "testthread.h"
#include "ui_testthread.h"

testthread::testthread(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::testthread)
{
    ui->setupUi(this);
}

testthread::~testthread()
{
    delete ui;
}

void testthread::on_pushButton_clicked()
{
    this->close();
}


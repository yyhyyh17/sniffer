#ifndef TESTTHREAD_H
#define TESTTHREAD_H

#include <QDialog>

namespace Ui {
class testthread;
}

class testthread : public QDialog
{
    Q_OBJECT

public:
    explicit testthread(QWidget *parent = nullptr);
    ~testthread();

private slots:
    void on_pushButton_clicked();

private:
    Ui::testthread *ui;
};

#endif // TESTTHREAD_H

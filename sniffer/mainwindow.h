#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <mythread.h>
#include <QThread>
#include <QStandardItemModel>
#include <QVector>
#include <qhexview.h>
#include <tcp_trace.h>
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    const struct pcap_pkthdr * pkthdr;
    static int index;
    QVector<u_char*> pkt_data;
    QVector<int> pkt_len;
    Ui::MainWindow *ui;
    QHexView *disp;
    QString charTohex (u_char);
    u_int bigtosmall(int );
    QModelIndex table_index;
    int tcpmark;
private slots:
    //void jumpSlot();
    void tab_flush();
    void openThreadSlot();
    void closeThreadSlot();
    void finishedThreadSlot();
    void tcptrace();
    void updateSlot(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
    void getNetName(QString);
    void onTableClicked(const QModelIndex &);
    void Setflt();
signals:
    void sendFliter(QString);
private:
    QThread *curthread;
    mythread *sniffer = nullptr;
    static QStandardItemModel* tamodel;
};
#endif // MAINWINDOW_H

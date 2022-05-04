#ifndef TCP_TRACE_H
#define TCP_TRACE_H

#include <QDialog>
#include "pcap.h"
#include "mythread.h"
#include <qhexview.h>
#include <document/buffer/qmemoryrefbuffer.h>

namespace Ui {
class tcp_trace;
}

class tcp_trace : public QDialog
{
    Q_OBJECT

public:

    explicit tcp_trace(QVector<u_char*>* ,QVector<int>* pkt_len,int _row,QWidget *parent = nullptr);
    ~tcp_trace();
    QHexView *disp;
    QVector<u_char*>  pkt_data;
    QVector<int> pkt_len;
    int row;
    int len;
    u_char * next;
    QString charTohex (u_char);
private:
    Ui::tcp_trace *ui;
};

#endif // TCP_TRACE_H

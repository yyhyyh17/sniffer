#include "tcp_trace.h"
#include "ui_tcp_trace.h"
#include <cstring>
tcp_trace::tcp_trace(QVector<u_char*> *_pkt_data,QVector<int> *pkt_len,int _row,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::tcp_trace)
{
    this->pkt_data = *_pkt_data;
    this->row = _row;
    len = (*pkt_len)[this->row];
    const u_char * packet = pkt_data[row];
    ui->setupUi(this);
    disp = new QHexView(ui->widget);
    disp->setGeometry(QRect(QPoint(0,0),ui->widget->size()));
    disp->show();
    //QHexDocument* document=QHexDocument::fromMemory<QMemoryRefBuffer>((char*)pkt_data[row],len,disp);
    //disp->setDocument(document);
    char  res[100000];
    char  *res_input_mark=res;
    //QString Qpacket;
    memcpy(res,packet,len);
    res_input_mark += len;
    int totallen = 0;
    totallen += len;
    memcpy(res_input_mark,"--------------------",20);
    res_input_mark += 20;
    totallen += 20;
    //QByteArray temparray;
    QString source_ip;
    QString dest_ip;
    QString next_source_ip;
    QString next_dest_ip;
    int source_port;
    int dest_port;
    int next_source_port;
    int next_dest_port;

    int tmp_row;
    int continue_flag = 1;
    IPHEADER *ip_hdr = (IPHEADER*)(packet+14);
    source_ip.append(QString::number(ip_hdr->sourceIP[0]));
    source_ip.append('.');
    source_ip.append(QString::number(ip_hdr->sourceIP[1]));
    source_ip.append('.');
    source_ip.append(QString::number(ip_hdr->sourceIP[2]));
    source_ip.append('.');
    source_ip.append(QString::number(ip_hdr->sourceIP[3]));

    dest_ip.append(QString::number(ip_hdr->destIP[0]));
    dest_ip.append('.');
    dest_ip.append(QString::number(ip_hdr->destIP[1]));
    dest_ip.append('.');
    dest_ip.append(QString::number(ip_hdr->destIP[2]));
    dest_ip.append('.');
    dest_ip.append(QString::number(ip_hdr->destIP[3]));

    TCPHEADER *tcp_hdr = (TCPHEADER*)((char *)(pkt_data[row]) + 14 + ip_hdr->header_len * 4);
    source_port = tcp_hdr->source_port_1 * 256 + tcp_hdr->source_port_2;
    dest_port = tcp_hdr->dest_port_1 * 256 + tcp_hdr->dest_port_2;

    for (int i = row+1; i < pkt_data.size();i++)
    {
        //qDebug()<<i;
        if (!continue_flag)
            break;
        tmp_row = i;
        next = pkt_data[tmp_row];
        //qDebug()<<pkt_data[tmp_row];
        IPHEADER *next_ip_hdr = (IPHEADER*)(next+14);
        TCPHEADER *next_tcp_hdr = (TCPHEADER*)((char *)(next) + 14 + next_ip_hdr->header_len * 4);
        next_source_ip.append(QString::number(next_ip_hdr->sourceIP[0]));
        next_source_ip.append('.');
        next_source_ip.append(QString::number(next_ip_hdr->sourceIP[1]));
        next_source_ip.append('.');
        next_source_ip.append(QString::number(next_ip_hdr->sourceIP[2]));
        next_source_ip.append('.');
        next_source_ip.append(QString::number(next_ip_hdr->sourceIP[3]));

        next_dest_ip.append(QString::number(next_ip_hdr->destIP[0]));
        next_dest_ip.append('.');
        next_dest_ip.append(QString::number(next_ip_hdr->destIP[1]));
        next_dest_ip.append('.');
        next_dest_ip.append(QString::number(next_ip_hdr->destIP[2]));
        next_dest_ip.append('.');
        next_dest_ip.append(QString::number(next_ip_hdr->destIP[3]));
        next_source_port = next_tcp_hdr->source_port_1 * 256 + next_tcp_hdr->source_port_2;
        next_dest_port = next_tcp_hdr->dest_port_1 * 256 + next_tcp_hdr->dest_port_2;
        if ((source_ip == next_source_ip && dest_ip == next_dest_ip
                && source_port == next_source_port && dest_port == next_dest_port) ||
                (source_ip == next_dest_ip && dest_ip == next_source_ip
                 && source_port == next_dest_port && dest_port == next_source_port))

        {
            qDebug()<<"match";
            //qDebug()<<source_ip<<'/'<<next_source_ip<<'/'<<dest_ip<<'/'<<next_dest_ip;
            qDebug()<<i;
            if (next_tcp_hdr->fin||next_tcp_hdr->rst)
                continue_flag = 0;
            else
            {
                qDebug()<<"mark";
                memcpy(res_input_mark ,next,(*pkt_len)[i]);
                res_input_mark += (*pkt_len)[i];
                totallen += (*pkt_len)[i];
                memcpy(res_input_mark,"--------------------",20);
                res_input_mark += 20;
                totallen += 20;
            }
        }
        next_dest_ip.clear();
        next_source_ip.clear();
        next_source_port = 0;
        next_dest_port = 0;
    }
    qDebug()<<"end";
    QHexDocument* document=QHexDocument::fromMemory<QMemoryRefBuffer>(res,totallen,disp);
    disp->setDocument(document);


}

tcp_trace::~tcp_trace()
{
    delete ui;
}

QString tcp_trace::charTohex(u_char  num)
{
    QString res = "";
    //qDebug ()<<int(num);
    int fir = int(num) / 16;
    //qDebug ()<<fir;
    int sec = int(num) % 16;
    //qDebug ()<<sec;
    if (fir < 10)
    {
        res += '0' + fir;
    }
    else res += 'a' + fir -10;
    if (sec < 10)
    {
        res += '0' + sec;
    }
    else res += 'a' + sec -10;

    return res;

}

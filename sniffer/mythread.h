#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QObject>
#include "pcap.h"
#include <QDebug>
#include <atomic>
typedef struct
{
    u_char Destmac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;

typedef struct
{
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];

}IPHEADER;

typedef struct
{
    u_char source_port_1:8;
    u_char source_port_2:8;
    u_char dest_port_1:8;
    u_char dest_port_2:8;
    int seq:32;
    int ack:32;
    u_char shifting:10;
    u_char urg:1;
    u_char ack_mark:1;
    u_char psh:1;
    u_char rst:1;
    u_char syn:1;
    u_char fin:1;
    u_char window:16;
    u_char checksum:16;
    u_char urgency:16;
    int useless:32;

}TCPHEADER;

typedef struct
{
    u_char source_port_1:8;
    u_char source_port_2:8;
    u_char dest_port_1:8;
    u_char dest_port_2:8;
    u_char pkt_len_1:8;
    u_char pkt_len_2:8;
}UDPHEADER;


typedef struct
{
   u_char type:8;
   u_char code:8;
   u_char checksum_1:8;
   u_char checksum_2:8;
}ICMPHEADER;

static char * Proto[] = {"Reserved","ICMP","IGMP","GGP","IP","ST","TCP"};
class mythread: public QObject
{
    Q_OBJECT
public:
    explicit mythread(QObject *parent = nullptr);
    void closeThead();
    static void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
    QByteArray  fliter;
signals:
public slots:
    void startThreadSlot();
    void capture_pkts();
    void setFliter(QString);
signals:
    void updateSignal(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
    void sendNetName(QString);
private:
    volatile bool isStop;
    static mythread* instance;
    static std::atomic_bool should_die;
};


#endif // MYTHREAD_H

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include <QDebug>
#include <QString>
#include <iostream>
#include <document/buffer/qmemoryrefbuffer.h>
#include <QMessageBox>
QStandardItemModel * MainWindow::tamodel;
int MainWindow::index = 0;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow())

{
    ui->setupUi(this);
    tcpmark =0;
    //ui->pushButton_2->setText("capture");
    ui->textEdit->setReadOnly(true);
    disp = new QHexView(ui->widget);
    disp->setGeometry(QRect(QPoint(0,0),ui->widget->size()));
    disp->show();
    tamodel = new QStandardItemModel;
    tamodel->setColumnCount(5);
    tamodel->setHeaderData(0,Qt::Horizontal,"id");
    tamodel->setHeaderData(1,Qt::Horizontal,"len");
    tamodel->setHeaderData(2,Qt::Horizontal,"source");
    tamodel->setHeaderData(3,Qt::Horizontal,"dest");
    tamodel->setHeaderData(4,Qt::Horizontal,"type");
    ui->tableView->setModel(tamodel);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(ui->tableView,SIGNAL(clicked(const QModelIndex &)),
            this,SLOT(onTableClicked(const QModelIndex &)));

    ui->device_label->setText("decive name:");

    //connect(ui->pushButton,SIGNAL(clicked(bool)),this,SLOT(tab_flush()));
    //connect(ui->pushButton_2,SIGNAL(clicked(bool)),this,SLOT(openThreadSlot()));

    //connect(ui->pushButton_3,SIGNAL(clicked(bool)),this,SLOT(closeThreadSlot()));

    connect(ui->pushButton,SIGNAL(clicked(bool)),this,SLOT(tcptrace()));

    connect(ui->flt,SIGNAL(clicked(bool)),this,SLOT(Setflt()));

    curthread = new QThread;
    sniffer = new mythread;
    sniffer->moveToThread(curthread);
    connect(curthread,SIGNAL(finished()),sniffer,SLOT(deleteLater()));
    connect(curthread,SIGNAL(finished()),this,SLOT(finishedThreadSlot()));

    connect(ui->pushButton_2,SIGNAL(clicked()),sniffer,SLOT(capture_pkts()));

    connect(sniffer,SIGNAL(updateSignal(u_char *, const struct pcap_pkthdr *, const u_char *)),
            this,SLOT(updateSlot(u_char *, const struct pcap_pkthdr *, const u_char *)));

    connect(sniffer,SIGNAL(sendNetName(QString)),
            this,SLOT(getNetName(QString)));

    connect(this,SIGNAL(sendFliter(QString)),sniffer,SLOT(setFliter(QString)));

    curthread->start();

}




MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow::tab_flush()
{
    ui->tableView->setModel(tamodel);
    return;
}

void MainWindow::openThreadSlot()
{
    //ui->pushButton_2->setText("capture");
    //qDebug()<<tr("running openThreadSlot");
    //this->emit sendFliter(ui->lineEdit->text());
    curthread->start();
    //qDebug()<<"mainwindow QThread::currentThreadId()=="<<QThread::currentThreadId();
    return;
}



void MainWindow::closeThreadSlot()
{
    qDebug()<<tr("closing thread");
    if (curthread->isRunning())
    {
        sniffer->closeThead();
        curthread->quit();
        curthread->wait();
    }
    return;
}




void MainWindow::finishedThreadSlot()
{
    qDebug()<<tr("multi-thread occured");
    return;
}

void MainWindow::updateSlot(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    //qDebug()<<"packet achieved";
    u_char* tmp_pkt = new u_char[pkthdr->caplen];
    memcpy(tmp_pkt,packet,pkthdr->caplen);
    pkt_data.append(tmp_pkt);
    pkt_len.append(pkthdr->caplen);
    QList<QStandardItem*> list;
    QString source_ip;
    QString dest_ip;
    ETHHEADER *eth_hdr = (ETHHEADER*) packet;
    if (pkthdr->len > 14)
    {
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

        char strType[100];
        if(ip_hdr->proto > 7)
            list << new QStandardItem(QString::number(index)) << new QStandardItem(QString::number(pkthdr->len))
                 << new QStandardItem(source_ip)<<new QStandardItem(dest_ip)<<new QStandardItem("UDP");
        else
            list << new QStandardItem(QString::number(index)) << new QStandardItem(QString::number(pkthdr->len))
                 << new QStandardItem(source_ip)<<new QStandardItem(dest_ip)<<new QStandardItem(Proto[ip_hdr->proto]);

    }
    tamodel->insertRow(index++, list);
    //ui->tableView->setModel(tamodel);
    //qDebug()<<"testing";
    return;
}

void MainWindow::getNetName(QString device)
{
    ui->label->setText(device);
    return;
}

void MainWindow::tcptrace()
{
    if (!tcpmark)
    {
        QMessageBox::information(NULL,"error","this is not a tcp protocal!"
                                 ,QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        return;
    }

    tcp_trace a(&pkt_data,&pkt_len,table_index.row());
    a.exec();
    return;
}

void MainWindow::onTableClicked(const QModelIndex &tmp)
{
    /*
    char * test1 = "abc";
    char * test2 = "efg";
    QString test3 = QString(test1) + QString(test2);
    qDebug()<<(test3);
    QByteArray tmp_array = test3.toLatin1();
    test1 = tmp_array.data();
    for(int i =0 ;i<6;i++) qDebug()<<(test1[i]);
    */
    int port;
    int acknowledge;
    int sequcence;
    ui->textEdit->clear();
    QByteArray temp1;
    QString input_line= "";
    QModelIndex pindex;
    //qDebug()<< tmp.row();
    QHexDocument* document=QHexDocument::fromMemory<QMemoryRefBuffer>((char*)pkt_data[tmp.row()],
            pkt_len[tmp.row()],disp);
    disp->setDocument(document);
    ETHHEADER *eth_hdr = (ETHHEADER*) pkt_data[tmp.row()];
    IPHEADER *ip_hdr = (IPHEADER *) ((char *)(pkt_data[tmp.row()]) + 14);
    for (int i = 0;i < 1;i++)
    {
        input_line.append("source mac: ");
        input_line.append(charTohex(eth_hdr->SrcMac[0]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->SrcMac[1]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->SrcMac[2]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->SrcMac[3]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->SrcMac[4]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->SrcMac[5]));

        input_line.append("  dest mac: ");
        input_line.append(charTohex(eth_hdr->Destmac[0]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->Destmac[1]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->Destmac[2]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->Destmac[3]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->Destmac[4]));
        input_line.append(".");
        input_line.append(charTohex(eth_hdr->Destmac[5]));
        input_line.append('\n');

        input_line.append("source ip: ");
        input_line.append(QString::number(ip_hdr->sourceIP[0]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->sourceIP[1]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->sourceIP[2]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->sourceIP[3]));

        input_line.append("  dest ip: ");
        input_line.append(QString::number(ip_hdr->destIP[0]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->destIP[1]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->destIP[2]));
        input_line.append('.');
        input_line.append(QString::number(ip_hdr->destIP[3]));
        input_line.append('\n');

        if (ip_hdr->proto == 1)
        {
            tcpmark = 0;
            ICMPHEADER *icmp_hdr = (ICMPHEADER*)((char *)(pkt_data[tmp.row()]) + 14 + ip_hdr->header_len * 4);
            QString temp_string;
            input_line.append("protocol: ICMP");
            input_line.append('\n');
            input_line.append("ICMP type:");
            input_line.append(QString::number(icmp_hdr->type));
            if(icmp_hdr->type == 8)
                input_line.append(" (request)");
            else
                input_line.append(" (reply)");

            input_line.append('\n');
            input_line.append("ICMP code:");
            input_line.append(QString::number(icmp_hdr->code));
            input_line.append('\n');
            input_line.append("check sum:");
            input_line.append("0x");
            input_line.append(charTohex(icmp_hdr->checksum_1));
            input_line.append(charTohex(icmp_hdr->checksum_2));

        }

        if (ip_hdr->proto == 6)
        {
            tcpmark = 1;
            TCPHEADER *tcp_hdr = (TCPHEADER*)((char *)(pkt_data[tmp.row()]) + 14 + ip_hdr->header_len * 4);
            port = tcp_hdr->source_port_1 * 256 + tcp_hdr->source_port_2;
            input_line.append("protocol: TCP");
            input_line.append('\n');
            input_line.append("source port:");
            input_line.append(QString::number(port));
            port = tcp_hdr->dest_port_1 * 256 + tcp_hdr->dest_port_2;
            input_line.append("dest port:");
            input_line.append(QString::number(port));
            input_line.append('\n');
            input_line.append("seq:");
            input_line.append(QString::number(bigtosmall(tcp_hdr->seq)));
            input_line.append("  ack:");
            input_line.append(QString::number(bigtosmall(tcp_hdr->ack)));
        }
        if (ip_hdr->proto == 17)
        {
            tcpmark = 0;
            UDPHEADER *udp_hdr = (UDPHEADER*)((char *)(pkt_data[tmp.row()]) + 14 + ip_hdr->header_len * 4);
            port = udp_hdr->source_port_1 * 256 + udp_hdr->source_port_2;
            input_line.append("protocol: UDP");
            input_line.append('\n');
            input_line.append("source port:");
            input_line.append(QString::number(port));
            port = udp_hdr->dest_port_1 * 256 + udp_hdr->dest_port_2;
            input_line.append("dest port:");
            input_line.append(QString::number(port));
            input_line.append('\n');
            input_line.append("packet length:");
            port = udp_hdr->pkt_len_1 * 256 +udp_hdr->pkt_len_2;
            input_line.append(QString::number(port));
        }
        //pindex = tamodel->index(tmp.row(),i);
        //input_line += tamodel->data(pindex).toString();

    }
    ui->textEdit->append(input_line);
    this->table_index = tmp;
    return;
}

void MainWindow::Setflt()
{
    //qDebug()<<1;
    bool restart=(sniffer!=nullptr);
    if(restart){
    sniffer->closeThead();

    QEventLoop * ev=new QEventLoop();
    ev->connect(sniffer,&mythread::destroyed,ev,[&ev](){ev->quit();});
    ev->exec();
    ev->deleteLater();

    sniffer = new mythread;
    tamodel->removeRows(0,tamodel->rowCount());
    pkt_data.clear();
    pkt_len.clear();
    index = 0;
    sniffer->moveToThread(curthread);

    connect(curthread,SIGNAL(finished()),sniffer,SLOT(deleteLater()));
    connect(ui->pushButton_2,SIGNAL(clicked()),sniffer,SLOT(capture_pkts()));
    connect(sniffer,SIGNAL(updateSignal(u_char *, const struct pcap_pkthdr *, const u_char *)),
            this,SLOT(updateSlot(u_char *, const struct pcap_pkthdr *, const u_char *)));
    connect(sniffer,SIGNAL(sendNetName(QString)),
            this,SLOT(getNetName(QString)));
    connect(this,SIGNAL(sendFliter(QString)),sniffer,SLOT(setFliter(QString)));
    }
    this->emit sendFliter(ui->lineEdit->text());
    if(restart){
        ui->pushButton_2->click();
    }
    return;
}

QString MainWindow::charTohex(u_char  num)
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

u_int MainWindow::bigtosmall(int a)
{
    char tmp1,tmp2,tmp3,tmp4;
    u_int res = 0;
    tmp1 = 0xff & (a>> 24);
    tmp2 = 0xff & (a>> 16);
    tmp3 = 0xff & (a>> 8);
    tmp4 = 0xff & a;
    res += tmp1;
    res += tmp2 * (1<<8);
    res += tmp3 * (1<<16);
    res += tmp4 * (1<<24);
    return res;
}

#include "mythread.h"
#include <QDebug>
#include <QThread>
mythread* mythread::instance;
std::atomic_bool mythread::should_die;
mythread::mythread(QObject * parent):QObject(parent)
{
    isStop = false;
    instance=this;
    should_die = false;
    fliter = "ip proto TCP";
    //qDebug()<<"123";
    connect(this,&QObject::destroyed,this,[](){
        qDebug()<<"old thread destroyed";
    });
}

void mythread::closeThead()
{
    isStop = true;
    should_die = true;
    qDebug()<<"CloseThread";
}

void mythread::startThreadSlot()
{
    while(true)
    {
        if (isStop)
            return;
        qDebug()<<"Mythread::startThreadSlot QThread::currentThreadId()=="<<QThread::currentThreadId();
        QThread::sleep(1);
    }
}

void mythread::capture_pkts()
{
    //qDebug()<<3;
    char errBuf[PCAP_ERRBUF_SIZE], *device;
      //pcap_t * cur_port;
    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    device = pcap_lookupdev(errBuf);
    instance->emit sendNetName(device);
      //device = "test device";
      if (device)
      {
        qDebug()<<"success: device: "<<device;
      }
      else
      {
        qDebug()<<"error:"<< errBuf;
        exit(1);
      }
      //this->ui->label->setText(device);
      //pcap_t * device_p = pcap_open_live(device, 65535000, 1, 0, errBuf);
      pcap_t* device_p = NULL;
      device_p = pcap_create(device,errBuf);
      if(!device_p)
      {
        exit(1);
      }
      if (pcap_lookupnet(device,&ipaddress,&ipmask,errBuf) == -1)
      {
          exit(1);
      }
      else
      {
          char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
          if (inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
              exit(1);
          else if (inet_ntop(AF_INET,&ipmask,mask,sizeof(ip))==NULL)
              exit(1);
          //qDebug()<<ip<<mask<<Proto[6];
      }



      pcap_set_immediate_mode(device_p,1);
      int ret = pcap_activate(device_p);
      int id = 0;
      //qDebug()<<"flag1";
       //qDebug()<<QString(QLatin1String( instance->fliter));
      //qDebug()<<"flag2";
       pcap_compile(device_p,&fcode,instance->fliter.data(),1,0);
       //qDebug()<<"flag3";
      pcap_setfilter(device_p,&fcode);
      pcap_loop(device_p, -1, getPacket, (u_char*)device_p);
      //qDebug()<<"Returning from loop";
      pcap_close(device_p);
      this->deleteLater();

}

void mythread::getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    if(should_die){
        //qDebug()<<"BreakLoop";
        pcap_breakloop((pcap_t*)arg);
        return;
    }
    //qDebug()<<"getPacket";
  int * id = (int *)arg;
  int len = *id;
  //qDebug()<<("id: %d\n", ++(*id));
  //qDebug()<<("Packet length: %d\n", pkthdr->len);
  //qDebug()<<("Number of bytes: %d\n", pkthdr->caplen);
  //qDebug()<<("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    /*
  int i;
  for(i=0; i<pkthdr->len; ++i)
  {
    qDebug()<<(" %02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      qDebug()<<("\n");
    }
  }
  */
  //qDebug()<<("packet achieved!");

  instance->emit updateSignal(arg,pkthdr,packet);
}

void mythread::setFliter(QString flt)
{
    //qDebug()<<2;
    fliter = flt.toLatin1();
    //this->fliter = tmp.data();
    //qDebug()<<instance->fliter;
}

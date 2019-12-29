#pragma once
#define HAVE_REMOTE
#include "pcap.h"
#include <QtWidgets/QMainWindow>
#include "qstring.h"
#include "ui_QtGuiApplication5.h"
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答
#define PROTO_TCP 6 
#define PROTO_UDP 17
#define MAX_BUFF_LEN 65500 
using namespace std;


//14字节以太网首部
struct EthernetHeader
{
	u_char DestMAC[6];    //目的MAC地址 6字节
	u_char SourMAC[6];   //源MAC地址 6字节
	u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct ArpHeader
{
	unsigned short hdType;   //硬件类型
	unsigned short proType;   //协议类型
	unsigned char hdSize;   //硬件地址长度
	unsigned char proSize;   //协议地址长度
	unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];   //源MAC地址
	unsigned char sip[4];   //源IP地址
	u_char dmac[6];   //目的MAC地址
	unsigned char dip[4];   //目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

//定义ip头
struct IpHeader
{
	unsigned char       h_verlen; //4位ip版本号，4位头部长度
	unsigned char       tos;//8位服务类型
	unsigned short      total_len;//16位总长度
	unsigned short      ident;//16位标识
	unsigned short      frag_and_flags;//3位标志位
	unsigned char       ttl;//8位生存时间
	unsigned char       proto;//8位协议
	unsigned short      checksum;//16位ip头部检验和
	unsigned int        sourceIP;//32位源ip地址
	unsigned int        destIP;//32位目的ip地址
};

//定义tcp头
struct TcpHeader
{
	unsigned short    th_sport;//16位源端口
	unsigned short    th_dport;//16位目的端口
	unsigned int    th_seq;//32位序列号
	unsigned int    th_ack;//32位确认号
	unsigned char    th_lenres;//4位头部长度/6位保留字
	unsigned char    th_flag;//6位标志位
	unsigned short    th_win;//16位窗口大小
	unsigned short    th_sum;//16位校验和
	unsigned short    th_urp;//16位紧急数据偏移量
};

//定义伪头部
struct Psdhdr {
	unsigned long    saddr;
	unsigned long    daddr;
	char            mbz;
	char            ptcl;
	unsigned short    plen;
};

//定义UDP头
struct UdpHeader
{
	u_short sport;		//源端口  16位
	u_short dport;		//目的端口 16位
	u_short len;			//数据报长度 16位
	u_short check;		//校验和 16位	
};

class QtGuiApplication5 : public QMainWindow
{
	Q_OBJECT
public slots:
	void send_clicked();
public:
	QtGuiApplication5(QWidget *parent = Q_NULLPTR);
	
	pcap_if_t *alldevs;   //所有网络适配器
	pcap_if_t *d;   //选中的网络适配器 
	int inum;   //选择网络适配器
	pcap_t *adhandle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	Ui::QtGuiApplication5Class ui;
};

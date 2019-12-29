#pragma once
#define HAVE_REMOTE
#include "pcap.h"
#include <QtWidgets/QMainWindow>
#include "qstring.h"
#include "ui_QtGuiApplication5.h"
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1   //ARP����
#define ARP_RESPONSE       2      //ARPӦ��
#define PROTO_TCP 6 
#define PROTO_UDP 17
#define MAX_BUFF_LEN 65500 
using namespace std;


//14�ֽ���̫���ײ�
struct EthernetHeader
{
	u_char DestMAC[6];    //Ŀ��MAC��ַ 6�ֽ�
	u_char SourMAC[6];   //ԴMAC��ַ 6�ֽ�
	u_short EthType;         //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};

//28�ֽ�ARP֡�ṹ
struct ArpHeader
{
	unsigned short hdType;   //Ӳ������
	unsigned short proType;   //Э������
	unsigned char hdSize;   //Ӳ����ַ����
	unsigned char proSize;   //Э���ַ����
	unsigned short op;   //�������ͣ�ARP����1����ARPӦ��2����RARP����3����RARPӦ��4����
	u_char smac[6];   //ԴMAC��ַ
	unsigned char sip[4];   //ԴIP��ַ
	u_char dmac[6];   //Ŀ��MAC��ַ
	unsigned char dip[4];   //Ŀ��IP��ַ
};

//��������arp���İ����ܳ���42�ֽ�
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

//����ipͷ
struct IpHeader
{
	unsigned char       h_verlen; //4λip�汾�ţ�4λͷ������
	unsigned char       tos;//8λ��������
	unsigned short      total_len;//16λ�ܳ���
	unsigned short      ident;//16λ��ʶ
	unsigned short      frag_and_flags;//3λ��־λ
	unsigned char       ttl;//8λ����ʱ��
	unsigned char       proto;//8λЭ��
	unsigned short      checksum;//16λipͷ�������
	unsigned int        sourceIP;//32λԴip��ַ
	unsigned int        destIP;//32λĿ��ip��ַ
};

//����tcpͷ
struct TcpHeader
{
	unsigned short    th_sport;//16λԴ�˿�
	unsigned short    th_dport;//16λĿ�Ķ˿�
	unsigned int    th_seq;//32λ���к�
	unsigned int    th_ack;//32λȷ�Ϻ�
	unsigned char    th_lenres;//4λͷ������/6λ������
	unsigned char    th_flag;//6λ��־λ
	unsigned short    th_win;//16λ���ڴ�С
	unsigned short    th_sum;//16λУ���
	unsigned short    th_urp;//16λ��������ƫ����
};

//����αͷ��
struct Psdhdr {
	unsigned long    saddr;
	unsigned long    daddr;
	char            mbz;
	char            ptcl;
	unsigned short    plen;
};

//����UDPͷ
struct UdpHeader
{
	u_short sport;		//Դ�˿�  16λ
	u_short dport;		//Ŀ�Ķ˿� 16λ
	u_short len;			//���ݱ����� 16λ
	u_short check;		//У��� 16λ	
};

class QtGuiApplication5 : public QMainWindow
{
	Q_OBJECT
public slots:
	void send_clicked();
public:
	QtGuiApplication5(QWidget *parent = Q_NULLPTR);
	
	pcap_if_t *alldevs;   //��������������
	pcap_if_t *d;   //ѡ�е����������� 
	int inum;   //ѡ������������
	pcap_t *adhandle;   //����������������׽ʵ��,��pcap_open���صĶ���
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	Ui::QtGuiApplication5Class ui;
};

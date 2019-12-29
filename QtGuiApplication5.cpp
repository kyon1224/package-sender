#include "QtGuiApplication5.h"

QtGuiApplication5::QtGuiApplication5(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/*����������д�ϱ������豸*/
	QStringList list;
	for (d = alldevs; d; d = d->next)
	{
		QString temp = (QString)(d->name)+" "+(QString)(d->description);
		list << temp;
	}
	ui.comboBox->addItems(list);

	connect(ui.pushButton, SIGNAL(clicked()), this, SLOT(send_clicked()));
}


unsigned short CheckSum(unsigned short * buffer, int size)//��������
{
	unsigned long   cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}


//���ͺ���
void  QtGuiApplication5::send_clicked() {
	inum = ui.comboBox->currentIndex()+1;
	/* ��ת��ѡ�е������� */
	int i = 0;   //forѭ������
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
	}

	/*tcpЭ�� */
	if (ui.comboBox_2->currentIndex() == 0) {
		string bb = ui.lineEdit_8->text().toStdString();
		char *temp = new char[bb.size() + 1];
		strcpy(temp, bb.c_str());//tempΪ��������  bb.size() Ϊ��С
		EthernetHeader eh;
		IpHeader ih;
		TcpHeader th;
		Psdhdr psh;
		u_char sendbuf[MAX_BUFF_LEN];
		
		//���
		//��̫��
		eh.DestMAC[0] = 0x8c;
		eh.DestMAC[1] = 0xa6;
		eh.DestMAC[2] = 0xdf;
		eh.DestMAC[3] = 0x94;
		eh.DestMAC[4] = 0x94;
		eh.DestMAC[5] = 0x29;
		eh.SourMAC[0] = 0x80;
		eh.SourMAC[1] = 0x2b;
		eh.SourMAC[2] = 0xf9;
		eh.SourMAC[3] = 0x72;
		eh.SourMAC[4] = 0x5f;
		eh.SourMAC[5] = 0xad;
		eh.EthType = htons(ETH_IP);

		//ipͷ��
		ih.h_verlen = (4 << 4 | sizeof(ih) / sizeof(unsigned int));
		ih.tos = 0;
		ih.total_len = htons((unsigned short)(sizeof(IpHeader) + sizeof(TcpHeader) + bb.size()));
		ih.ident = 1;
		ih.frag_and_flags = 0x40;
		ih.ttl = ui.lineEdit_3->text().toInt();
		ih.proto = PROTO_TCP;
		ih.checksum = 0;
		string te1 = ui.lineEdit->text().toStdString();
		string te2 = ui.lineEdit_2->text().toStdString();
		char *te11 = new char[te1.size() + 1];
		char *te22 = new char[te2.size() + 1];
		strcpy(te11, te1.c_str());
		strcpy(te22, te2.c_str());
		ih.sourceIP = inet_addr(te11);
		ih.destIP = inet_addr(te22);
		//tcpαͷ��
		psh.saddr = ih.sourceIP;
		psh.daddr = ih.destIP;
		psh.mbz = 0;
		psh.ptcl = ih.proto;
		psh.plen = htons(sizeof(TcpHeader) + bb.size());

		//tcp
		th.th_sport = htons(ui.lineEdit_6->text().toInt());//Դ�˿�
		th.th_dport = htons(ui.lineEdit_22->text().toInt());//Ŀ�Ķ˿�
		th.th_seq = htonl(ui.lineEdit_5->text().toInt());//���к�
		th.th_ack = ui.lineEdit_23->text().toInt();//ȷ�Ϻ�
		th.th_lenres = (sizeof(TcpHeader) / 4 << 4 | 0);//tcp����
		th.th_flag = (u_char)ui.lineEdit_4->text().toInt();//��־
		th.th_win = htons(ui.lineEdit_7->text().toInt());//���ڴ�С
		th.th_sum = 0;//У�����ʱ��Ϊ0
		th.th_urp = 0;//ƫ��
		
		//����У���
		memcpy(sendbuf, &psh, sizeof(Psdhdr));
		memcpy(sendbuf + sizeof(Psdhdr), &th, sizeof(TcpHeader));
		memcpy(sendbuf + sizeof(Psdhdr) + sizeof(TcpHeader), temp, bb.size());
		th.th_sum = CheckSum((unsigned short *)sendbuf, sizeof(Psdhdr) + sizeof(TcpHeader) + bb.size());//tcp
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &ih, sizeof(IpHeader));
		ih.checksum = CheckSum((unsigned short *)sendbuf, sizeof(IpHeader));//ip
		
		//��䷢�ͻ�����
		memset(sendbuf, 0, MAX_BUFF_LEN);
		memcpy(sendbuf, (void *)&eh, sizeof(EthernetHeader));
		memcpy(sendbuf + sizeof(EthernetHeader), (void *)&ih, sizeof(IpHeader));
		memcpy(sendbuf + sizeof(EthernetHeader) + sizeof(IpHeader), (void *)&th, sizeof(TcpHeader));
		memcpy(sendbuf + sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(TcpHeader), temp, bb.size());
		int siz = sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(TcpHeader) + bb.size();
		//����
		if (pcap_sendpacket(adhandle, sendbuf, siz) == 0) {
			ui.textBrowser->append(" TCP Packet send succeed");
		}
		else {
			ui.textBrowser->append("error");
		}

	}


	/*udpЭ��*/
	if (ui.comboBox_2->currentIndex() == 1) {
		u_char sendbuf[MAX_BUFF_LEN];
		EthernetHeader eh;
		IpHeader ih;
		UdpHeader uh;
		Psdhdr psh;
		string bb = ui.lineEdit_14->text().toStdString();
		char *temp = new char[bb.size() + 1];
		strcpy(temp, bb.c_str());//tempΪ��������
		//��̫��
		eh.EthType = htons(ETH_IP);
		eh.DestMAC[0] = 0x8c;
		eh.DestMAC[1] = 0xa6;
		eh.DestMAC[2] = 0xdf;
		eh.DestMAC[3] = 0x94;
		eh.DestMAC[4] = 0x94;
		eh.DestMAC[5] = 0x29;
		eh.SourMAC[0] = 0x80;
		eh.SourMAC[1] = 0x2b;
		eh.SourMAC[2] = 0xf9;
		eh.SourMAC[3] = 0x72;
		eh.SourMAC[4] = 0x5f;
		eh.SourMAC[5] = 0xad;

		//ip
		ih.h_verlen = (4 << 4 | sizeof(ih) / sizeof(unsigned int));//ip����ͷ�ܳ��ȳ���4
		ih.tos = 0;
		ih.total_len = htons((unsigned short)(sizeof(IpHeader)+sizeof(UdpHeader)+bb.size()));//��ipһֱ����ĩβ���ܳ���
		ih.ident = htons(1);
		ih.frag_and_flags = htons(0);
		ih.ttl = ui.lineEdit_11->text().toInt();
		ih.proto = PROTO_UDP;
		ih.checksum = 0;
		string te1 = ui.lineEdit_9->text().toStdString();
		string te2 = ui.lineEdit_10->text().toStdString();
		char *te11 = new char[te1.size() + 1];
		char *te22 = new char[te2.size() + 1];
		strcpy(te11, te1.c_str());
		strcpy(te22, te2.c_str());
		ih.sourceIP = inet_addr(te11);
		ih.destIP = inet_addr(te22);
	

		//udp
		uh.sport = htons(ui.lineEdit_12->text().toInt());
		uh.dport = htons(ui.lineEdit_13->text().toInt());
		uh.check = 0;
		uh.len = htons(sizeof(UdpHeader)+bb.size());


		//udpαͷ��
		psh.daddr = ih.destIP;
		psh.saddr = ih.sourceIP;
		psh.ptcl = PROTO_UDP;
		psh.mbz = 0;
		psh.plen = htons(sizeof(UdpHeader) + bb.size());

		//����У���
		memcpy(sendbuf, &psh, sizeof(psh));
		memcpy(sendbuf + sizeof(psh), &uh, sizeof(uh));
		memcpy(sendbuf + sizeof(psh) + sizeof(uh), temp, bb.size());
		uh.check = CheckSum((unsigned short *)sendbuf, sizeof(psh) + sizeof(uh)+bb.size());
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &ih, sizeof(ih));
		ih.checksum = CheckSum((unsigned short *)sendbuf, sizeof(ih));

		//���
		memset(sendbuf, 0, MAX_BUFF_LEN);
		memcpy(sendbuf, (void *)&eh, sizeof(EthernetHeader));
		memcpy(sendbuf + sizeof(EthernetHeader), (void *)&ih, sizeof(IpHeader));
		memcpy(sendbuf + sizeof(EthernetHeader) + sizeof(IpHeader), (void *)&uh, sizeof(UdpHeader));
		memcpy(sendbuf + sizeof(EthernetHeader) + sizeof(IpHeader)+sizeof(UdpHeader), temp, bb.size());
		int siz = sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + bb.size();
		//����
		if (pcap_sendpacket(adhandle, sendbuf, siz) == 0) {
			ui.textBrowser->append(" UDP Packet send succeed");
		}
		else {
			ui.textBrowser->append("error");
		}

	}


	/*arpЭ��*/
	if (ui.comboBox_2->currentIndex() == 2) {

		//���ARP��
		unsigned char sendbuf[42]; //arp���ṹ��С��42���ֽ�

		unsigned char ip[4] = { 0x01,0x02,0x03,0x04 };
		EthernetHeader eh;
		ArpHeader ah;
		//��ֵMAC��ַ
		memset(eh.DestMAC, 0xff, 6);   //��̫���ײ�Ŀ��MAC��ַ��ȫΪ�㲥��ַ
		eh.SourMAC[0] = 0x80;
		eh.SourMAC[1] = 0x2b;
		eh.SourMAC[2] = 0xf9;
		eh.SourMAC[3] = 0x72;
		eh.SourMAC[4] = 0x5f;
		eh.SourMAC[5] = 0xad;
		memcpy(ah.smac, eh.SourMAC, 6);   //ARP�ֶ�ԴMAC��ַ
		memset(ah.dmac, 0xff, 6);   //ARP�ֶ�Ŀ��MAC��ַ
		QString te1 = ui.lineEdit_17->text();
		QString te2 = ui.lineEdit_18->text();;
		int ah1 = stol(te1.section('.', 0, 0).toStdString());
		int ah2 = stol(te1.section('.', 1, 1).toStdString());
		int ah3 = stol(te1.section('.', 2, 2).toStdString());
		int ah4 = stol(te1.section('.', 3, 3).toStdString());
		int ah5 = stol(te2.section('.', 0, 0).toStdString());
		int ah6 = stol(te2.section('.', 1, 1).toStdString());
		int ah7 = stol(te2.section('.', 2, 2).toStdString());
		int ah8 = stol(te2.section('.', 3, 3).toStdString());
		
		ah.sip[0] = ah1;
		ah.sip[1] = ah2;
		ah.sip[2] = ah3;
		ah.sip[3] = ah4;
		ah.dip[0] = ah5;
		ah.dip[1] = ah6;
		ah.dip[2] = ah7;
		ah.dip[3] = ah8;
	
		eh.EthType = htons(ETH_ARP);   //htons�����������޷��Ŷ�������ת���������ֽ�˳��
		ah.hdType = htons(ARP_HARDWARE);
		ah.proType = htons(ETH_IP);
		ah.hdSize = 6;
		ah.proSize = 4;
		ah.op = htons(ARP_REQUEST);

		//����һ��ARP����
		memset(sendbuf, 0, sizeof(sendbuf));   //ARP����
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		//������ͳɹ�
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
			ui.textBrowser->append(" ARP Packet send succeed");
		}
		else {
			ui.textBrowser->append("error");
		}
	}

}

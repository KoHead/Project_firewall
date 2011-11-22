#define __KERNEL__
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>	
#include <linux/tcp.h>	
#include <linux/udp.h>
#include <linux/icmp.h>

MODULE_LICENSE("GPL");		
MODULE_AUTHOR("Si ça marche : Vincent Maël - Millet Gaël, Si ça plante : Hugo Viricel");
MODULE_DESCRIPTION("Firewall-trop-bien");

struct nf_hook_ops input_filter;	
int ports_udp[3] = {80,21,69};
int ports_tcp[3] = {80,21,69};

char* protocoles[134] = {"HOPOPT","ICMP","IGMP","GGP","IP","ST","TCP","CBT","EGP","IGP","BBN-RCC-MON","NVP-II","PUP","ARGUS","EMCON","XNET","CHAOS","UDP","MUX","DCN-MEAS ","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","SEP","3PC","IDPR","XTP","DDP","IDPR-CMTP","TP++","IL","IPv6","SDRP","IPv6-Route","IPv6-Route","IDRP","RSVP","GRE","MHRP","BNA","ESP","AH","I-NLSP","SWIPE","NARP","MOBILE","TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","61","CFTP","63","SAT-EXPAK","KRYPTOLAN","RVD","IPPC","68","SAT-MON","VISA","IPCV","CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK","ISO-IP","VMTP","SECURE-VMTP","VINES","TTP","NSFNET-IGP","DGP","TCF","EIGRP","OSPFIGP","Sprite-RPC","LARP","MTP ","AX.25","IPIP","MICP","SCC-SP","ETHERIP","ENCAP","99","GMTP","IFMP","PNNI","PIM","ARIS","SCPS","QNX","A/N","IPComp","SNP","Compaq-Peer","IPX-in-IP","VRRP","PGM","114","L2TP","DDX","IATP","STP","SRP","UTI","SMP","SM","PTP","ISIS","FIRE ","CRTP","CRUDP","SSCOPMCE ","IPLT ","SPS","PIPE","SCTP","FC"}; // Le tableau est indexé par n° de protocole, donc par exemple le protocole n°6 correspond bien à TCP

struct Option {
	int Protocol;
	int Port; //TODO : Affectation d'un nom au lieu d'un n° de protocole
	int InOut; // 0 = Out - 1 = IN
	int Access; // 0 = DENY - 1 = ALLOW
	//TODO : gestion des IP
};
struct Option OptionsArray[2];

unsigned int input_hook(unsigned int hooknum, struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	
	int i;	
	int drop = 0;
	struct iphdr *iph;	
	iph = (struct iphdr *)skb_network_header(skb);
	for (i=0 ; i<2 ; i++)
	{
		if (OptionsArray[i].Protocol == iph->protocol)//TODO : bloquer tous les protocoles ?
		{
			if((iph->protocol == 6)||(iph->protocol == 17))
			{
				
				if(iph->protocol==6)
				{
					struct tcphdr *protoh;					
					protoh = (struct tcphdr *)skb_transport_header(skb);
					if((OptionsArray[i].Port==(int)protoh->source)||(OptionsArray[i].Port==(int)protoh->dest))
					{
						drop = 1;
						printk("<1>Firewall : A bloqué une ouverture de port !\n");
					}
				}
				else
				{
					struct udphdr *protoh;	
					protoh = (struct udphdr *)skb_transport_header(skb);
					if((OptionsArray[i].Port==(int)protoh->source)||(OptionsArray[i].Port==(int)protoh->dest))//TODO : Gestion IN/OUT distincte
					{
						drop = 1;
						printk("<1>Firewall : A bloqué une ouverture de port !\n");
					}
				}
				//TODO : Fontion pour tous les ports ?
				
			}
			else{
				drop = 1;
				printk("<1>Firewall : A bloqué un protocole !\n");
			}
			//TODO : Gestion des ALLOW/DENY ?
		}
	}
	if(drop==1){
		return NF_DROP;
	}
	else{
		return NF_ACCEPT;
	}
}

int init_module(void)
{
	int result;


	struct Option myOption;

	myOption.Protocol = 6;
	myOption.Port = 80;
	myOption.InOut = 0;
	myOption.Access = 0;
	OptionsArray[0] = myOption;
	myOption.Protocol = 1;
	myOption.Port = 20;
	myOption.InOut = 0;
	myOption.Access = 0;
	OptionsArray[1] = myOption;
	//TODO : chargement de OptionsArray depuis un fichier
	
	input_filter.list.next = NULL;
	input_filter.list.prev = NULL;
	
	input_filter.hook = (nf_hookfn *)input_hook;	
	input_filter.pf = PF_INET;			
	input_filter.hooknum = NF_INET_LOCAL_IN;

	

	result = nf_register_hook(&input_filter);
	if(result)
	{
		printk("<1>Firewall : Erreur nf_register_hook !\n");
		return 1;
	}
	printk("<1>Firewall : Chargement OK !\n");
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hook(&input_filter);
	printk("<1>Firewall : Programme déchargé.\n");
}

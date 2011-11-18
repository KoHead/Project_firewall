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


unsigned int input_hook(unsigned int hooknum, struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	//iph = (*skb)->nh.iph;	
	iph = (struct iphdr *)skb_network_header(skb);
	
	
	if(iph->protocol == 1)	// ICMP
	{
		icmph = (struct icmphdr *)skb_transport_header(skb);
		
		printk("<1>Firewall : A bloqué un ping les pings de 0x%s !\n", iph->saddr);
		
		return NF_DROP;	
	}
	else if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)skb_transport_header(skb);
	
		
		int posTCPsource = -1;
		int posTCPdest = -1;
		int i;
		int j;

		if (69==tcph->source)
		   		posTCPsource=1;

		for (i=0 ; (i<3)&&(posTCPsource==-1) ; i++)
	       		if (ports_tcp[i]==(int)tcph->source)
		   		posTCPsource=i;

		for (j=0 ; (j<3)&&(posTCPdest==-1) ; j++)
	       		if (ports_tcp[j]==(int)tcph->dest)
		   		posTCPdest=j;

		if((posTCPsource!=-1)||(posTCPdest!=-1)){
			printk("<1>Firewall : Bloque port TCP source %d!!\n", tcph->source);
			printk("<1>Firewall : Bloque port TCP dest %d!!\n", tcph->dest);

			return NF_DROP;
		}
	}
	else if(iph->protocol == 17) // UDP
	{
		udph = (struct udphdr *)skb_transport_header(skb);
		

		int posUDPsource = -1;
		int posUDPdest = -1;
		int i;
		int j;

		for (i=0 ; (i<3)&&(posUDPsource==-1) ; i++)
	       		if (ports_udp[i]==(int)udph->source)
		   		posUDPsource=i;

		for (j=0 ; (j<3)&&(posUDPdest==-1) ; j++)
	       		if (ports_udp[j]==(int)udph->dest)
		   		posUDPdest=j;

		if((posUDPsource!=-1)||(posUDPdest!=-1)){
			printk("<1>Firewall : Bloque port UDP source %d!!\n", udph->source);
			printk("<1>Firewall : Bloque port UDP dest %d!!\n", udph->dest);

			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

int init_module(void)
{
	int result;

	
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

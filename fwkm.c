#define __KERNEL__
#define MODULE

#include <linux/module.h>	//MODULE_LICENCE, ...
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>	// fonctions netfilter

#include <linux/ip.h>		// structure iphdr
#include <linux/tcp.h>		// structure tcphdr
#include <linux/udp.h>
#include <linux/icmp.h>

MODULE_LICENSE("GPL");		// informations sur le module
MODULE_AUTHOR("Julien STERCKEMAN");
MODULE_DESCRIPTION("Mini firewall");

struct nf_hook_ops input_filter;	// caracteristiques du hook

// fonction qui va etre appelee pour le hook
unsigned int input_hook(unsigned int hooknum, struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	//iph = (*skb)->nh.iph;	// skb est une structure contenant le paquet
	iph = (struct iphdr *)skb_network_header(skb);
				// cf /linux/sk_buff.h
	
	if(iph->protocol == 1)	// ICMP
	{
		// on prend l'en-tête icmp
		icmph = (struct icmphdr *)skb_transport_header(skb);
		
		printk("<1>firewall : aime pas les ping de 0x%x!!\n", iph->saddr);
		
		return NF_DROP;	// on ignore tous les paquets icmp
		// ceci est juste pour l'exemple, en réalité il ne
		// faudrait refuser que les ICMP_ECHO et pas tous,
		// sinon nous n'orions plus les erreurs Host Unreacheable...
	}
	/*else if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)skb_transport_header(skb);
	
		printk("<1>firewall : paquet tcp ports=%d portd=%d\n", 
				tcph->source, tcph->dest);

		// c'est ici que l'on vérifie les ports, les flags, ...
		// et que l'on décide si l'on accepte le paquet
		return NF_DROP;
	}
	else if(iph->protocol == 17)	// UDP
	{
		udph = (struct udphdr *)skb_transport_header(skb);
		
		printk("<1>firewall : paquet udp ports=%d portd=%d\n",
				udph->source, udph->dest);

		// pareil que pour tcp
	}*/
	
	// si ca passe les tests on accepte
	return NF_ACCEPT;
}

int init_module(void)	// fonction "main()" des modules
{
	int result;

	// on indique les caracteristiques du hook d'entree
	input_filter.list.next = NULL;	// le kernel va les remplir
	input_filter.list.prev = NULL;
	
	input_filter.hook = (nf_hookfn *)input_hook;	// fonction hook
	input_filter.pf = PF_INET;			// IPv4
	input_filter.hooknum = NF_INET_LOCAL_IN;		// type de hook

	// on peut faire aussi des hook NF_IP_LOCAL_OUT pour
	// empecher des troyens ou spywares et autres
	// et NF_IP_FORWARD pour filtrer au niveau de la passerelle

	result = nf_register_hook(&input_filter);	// retourne 0 si ok
	if(result)
	{
		printk("<1>firewall : erreur nf_register_hook !!!\n");
		return 1;
	}
	printk("<1>firewall : module charge.\n");
	return 0;
}

void cleanup_module(void)	// appelee par rmmod
{
	nf_unregister_hook(&input_filter);
	printk("<1>firewall : module decharge.\n");
}

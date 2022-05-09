//https://www.linuxjournal.com/article/7184                                                         writing the hook func
//https://www.howtoforge.com/reading-files-from-the-linux-kernel-space-module-driver-fedora-14      read file
//https://www.lynxbee.com/sending-and-receiving-data-from-user-space-and-kernel-using-netlink-sockets-communicating-between-the-kernel-and-user-space-in-linux-using-netlink-sockets/   netlink sockets
//https://github.com/danisfermi/firewall-kernel-module  similar project
//https://github.com/ashishraste/minifirewall   similar project

#define __KERNEL__
#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define NETLINK_TEST 17
#define MAX_IP_NUM 100
#define IP_LENGTH 15

MODULE_LICENSE("GPL");

static struct nf_hook_ops netfilter_ops_in; /* NF_IP_PRE_ROUTING */
static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */
static struct sock *socketptr = NULL;
static unsigned short ports[65536] = {0};   //0 ports are closed 1 ports are open  //TODO: change to short or smaller size
static char rejected_ips[MAX_IP_NUM][IP_LENGTH];
static int number_of_ips = 0;


/* Function prototype in <linux/netfilter> */


static int searchForIp(char* ip_address)
{
    int foundIndex = -1;
    int i = 0;
    for(; i < number_of_ips; i++)
    {
        if(strcmp(rejected_ips[i], ip_address) == 0)
        {
            foundIndex = i;
            break;
        }
    }

    return foundIndex;
}
static void nl_recv_msg (struct sk_buff *skb) {

    char query[50];
    char *ptr = &query[0];
    
    printk(KERN_INFO "Netlink socket initialization");
    
    memset(&query,0,sizeof(query));

    struct nlmsghdr *nlh = NULL;
    if(skb == NULL) {
        printk("skb is NULL \n");
        return ;
    }
    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "%s: received netlink message payload: %s\n", __FUNCTION__, NLMSG_DATA(nlh));

    strcpy(query,NLMSG_DATA(nlh));
    //printk(KERN_INFO "%s,%d",query);
    
    printk(KERN_INFO "%c",*ptr);
    if(*(++ptr) == 'i')
    {
        printk(KERN_INFO "New ip rule");
        char ip_address[16];
        ptr = ptr + 3;
        char *ip_add_ptr = ip_address;

        while(*ptr != ' ')
        {
            *ip_add_ptr = *ptr;
            ip_add_ptr++;
            ptr++;
        }
        *ip_add_ptr = '\0';

        char option = *(++ptr);
        //drop case
        if(option == 'd')
        {   
            if(number_of_ips == 100)
            {
                return;
            }
            
            printk(KERN_INFO "Drop");
            int ipIndex = searchForIp(ip_address);
            printk(KERN_INFO "ipIndex = %d", ipIndex);

            if(ipIndex == -1)
            {
                strcpy(rejected_ips[number_of_ips], ip_address);
                number_of_ips++;
            }
        }
        else if(option == 'a')
        {
            printk(KERN_INFO "Accept");

            int i = 0;
            int foundIndex = searchForIp(ip_address);

            printk(KERN_INFO "foundIndex = %d", foundIndex);
            //IP found delete it and shift others to left
            if(foundIndex != -1)
            {
                for(i = foundIndex; i < number_of_ips - 1; i++)
                {
                    strcpy(rejected_ips[i], rejected_ips[i + 1]);
                }
                number_of_ips--;
            }
        }
        
        /*
        char *ptr2;
        printk(KERN_INFO "IP Address:");
        
        for(ptr2 = ip_address;*ptr2 != '\0';ptr2++)
        {
            printk("%c",*ptr2);
        }
        */

        //TODO: Add/delete ip address to/from an array(linked list etc) according to 
        //drop/accept
        
    }
    else
    {
        printk(KERN_INFO "New port rule");

        char port[6];
        char *port_ptr = port;

        ptr = ptr + 2;

        while(*ptr != ' ')
        {
            *port_ptr = *ptr;
            port_ptr++;
            ptr++;
        }
        *port_ptr = '\0';

        long long_port_num;
        int port_num;
        kstrtol(port,10,&long_port_num);
        port_num = (int)long_port_num;

        printk(KERN_INFO "%d",port_num);

        //Critical section add mutex
        if(*(++ptr) == 'a')
        {
            ports[port_num - 1] = 1;
        }
        else
        {
            ports[port_num - 1] = 0;
        }
    }
}

struct netlink_kernel_cfg cfg = {
    .input = nl_recv_msg,
};

//Took this func from https://github.com/ggary9424/miniFirewall/blob/master/module/mf_km.c
void ip_hl_to_str(unsigned int ip, char *ip_str)
{
    /*convert hl to byte array first*/
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);
    ip_array[0] = (ip_array[3] | ip);
    ip_array[1] = (ip_array[2] | (ip >> 8));
    ip_array[2] = (ip_array[1] | (ip >> 16));
    ip_array[3] = (ip_array[0] | (ip >> 24));
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

int check_ip(struct sk_buff *skb)
{

    struct iphdr *ip_header = ip_hdr(skb);
    //struct iphdr *ipp = (struct iphdr *)skb_network_header(skb); // probably needs <linux/skbuff.h> 

    struct tcphdr *tcp_header = tcp_hdr(skb);
    struct udphdr *udp_header = udp_hdr(skb);

    printk(KERN_INFO "IP Rule check start");
    char source[16],dest[16];
    char source_ip_str[16];
    char dest_ip_str[16];

    //printk(KERN_INFO "%s",ip_str);
    
    snprintf(source, 16, "%pI4", &ip_header->saddr);        //https://stackoverflow.com/questions/9296835/convert-source-ip-address-from-struct-iphdr-to-string-equivalent-using-linux-ne
    snprintf(dest, 16, "%pI4", &ip_header->daddr);

    /*
    printk(KERN_INFO "%pI4", nthol(&ip_header->saddr));
    printk(KERN_INFO "%pI4", nthol(&ip_header->daddr));

    */

    /*
    //Works
    printk(KERN_INFO "%pI4", &ip_header->saddr);
    printk(KERN_INFO "%pI4", &ip_header->daddr);
    */

    printk(KERN_INFO "Source ip addr: %s",source);
    printk(KERN_INFO "Dest ip addr: %s",dest);
    printk(KERN_INFO "Source port: %i",ntohs(tcp_header->source));
    printk(KERN_INFO "Dest port: %i",ntohs(tcp_header->dest));

    //TODO: Iterate through saved ips 
    //If found return 0 (drop)
    //else return 1 (accept)

    int i;
    for(i = 0; i < number_of_ips; i++)
    {
        printk(KERN_INFO "Comparing...  %s AND %s", source, rejected_ips[i]);
        if(strcmp(source, rejected_ips[i]) == 0)
        {
            return NF_DROP;
        }
    }

    printk(KERN_INFO "Rule check ended");

    return NF_ACCEPT;
}

int check_port(struct sk_buff *skb)
{
    //https://man7.org/linux/man-pages/man7/ip.7.html IPPROTO_TCP and IPPROTO_UDP
    //https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

    struct iphdr *ip_header = ip_hdr(skb);

    if(ip_header->protocol == IPPROTO_TCP)
    {
        printk(KERN_INFO "TCP Packet");
        struct tcphdr *tcp_header = tcp_hdr(skb);
        int dest_port = ntohs(tcp_header->dest);

        if(ports[dest_port - 1] == 1)
        {
            return NF_ACCEPT;
        }

    }
    else if(ip_header->protocol == IPPROTO_UDP)
    {
        printk(KERN_INFO "UDP Packet");
        struct udphdr *udp_header = udp_hdr(skb);
        int dest_port = ntohs(udp_header->dest);
        printk(KERN_INFO "UDP Packet's dest port = %i", dest_port);
        printk(KERN_INFO "port is = %d", ports[dest_port]);
        if(ports[dest_port - 1] == 1)
        {
            return NF_ACCEPT;
        }

        //printk(skb->transport_header)
    }
    else{
        printk(KERN_INFO "wtf %d", ip_header->protocol);
    }
    return NF_DROP;    
}

unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

    int check_ip_result = check_ip(skb);
    int check_port_result = check_port(skb);

    printk(KERN_INFO "check_port_result = %d", check_port_result);
    printk(KERN_INFO "check_ip_result = %d", check_ip_result);


    if(check_port_result & check_ip_result)
    {
        return NF_ACCEPT;
    }
    
    return NF_DROP; /* Drop ALL Packets */
}

//echo "7" > /proc/sys/kernel/printk

int init_module()
{
    socketptr = netlink_kernel_create(&init_net,NETLINK_TEST, &cfg);
    printk(KERN_INFO "Firewall module initialization");
    
    netfilter_ops_in.hook                   =       main_hook;
    netfilter_ops_in.pf                     =       PF_INET;
    netfilter_ops_in.hooknum                =       NF_INET_PRE_ROUTING;    //was NF_IP_PRE_ROUTING 
    netfilter_ops_in.priority               =       NF_IP_PRI_FIRST;
    netfilter_ops_out.hook                  =       main_hook;
    netfilter_ops_out.pf                    =       PF_INET;
    netfilter_ops_out.hooknum               =       NF_INET_POST_ROUTING;
    netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;
    nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
    nf_register_hook(&netfilter_ops_out); /* register NF_IP_POST_ROUTING hook */
    
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Firewall module cleanup");

    sock_release(socketptr->sk_socket);
    nf_unregister_hook(&netfilter_ops_in); /*unregister NF_IP_PRE_ROUTING hook*/
    nf_unregister_hook(&netfilter_ops_out); /*unregister NF_IP_POST_ROUTING hook*/
}



/*
struct nf_hook_ops
{
        struct list_head list;
        nf_hookfn *hook;
        int pf;
        int hooknum;
        int priority;
};
*/

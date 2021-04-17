#include <queue.h>
#include "skel.h"
#include "time.h"
// 4 sets of 3 digit numbers + 4 dots
#define ADDR_MAXLEN 4*3 + 4

// Will define a size for the arp table equal to the number of
// devices on the network. For a larger newtwork a list could
// be implemented but this works for this homework's purpose
#define ARPT_CAP 6

// Structures for the route table and arp table
// Taken from laboratory 4
struct rtable_entry {
    uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
};

//https://www.geeksforgeeks.org/binary-search-tree-set-1-search-and-insertion/
struct bst_node { 
    struct rtable_entry key;
    struct bst_node* left;
    struct bst_node* right;
    int height;
};

int max(int a, int b)
{
    return (a > b)? a : b;
}

int height(struct bst_node *N)
{
    if (N == NULL)
        return 0;
    return N->height;
}

struct bst_node* newNode(struct rtable_entry item)
{
    struct bst_node* temp = (struct bst_node*)malloc(sizeof(struct bst_node));
    temp->key = item;
    temp->left = NULL;
    temp->right = NULL;
    temp->height = 1;
    return temp;
}

struct bst_node *rightRotate(struct bst_node *y)
{
    struct bst_node *x = y->left;
    struct bst_node *T2 = x->right;
 
    // Perform rotation
    x->right = y;
    y->left = T2;
 
    // Update heights
    y->height = max(height(y->left), height(y->right))+1;
    x->height = max(height(x->left), height(x->right))+1;
 
    // Return new root
    return x;
}

struct bst_node *leftRotate(struct bst_node *x)
{
    struct bst_node *y = x->right;
    struct bst_node *T2 = y->left;
 
    // Perform rotation
    y->left = x;
    x->right = T2;
 
    //  Update heights
    x->height = max(height(x->left), height(x->right))+1;
    y->height = max(height(y->left), height(y->right))+1;
 
    // Return new root
    return y;
}

int getBalance(struct bst_node *N)
{
    if (N == NULL)
        return 0;
    return height(N->left) - height(N->right);
}

struct bst_node* insert(struct bst_node* node, struct rtable_entry key)
{
    /* If the tree is empty, return a new node */
    if (node == NULL)
        return newNode(key);
    
    /* Otherwise, recur down the tree */
    if (key.prefix < node->key.prefix)
        node->left = insert(node->left, key);
    else if (key.prefix > node->key.prefix)
        node->right = insert(node->right, key);
    else
        return node;

    node->height = 1 + max(height(node->left), height(node->right));
    int balance = getBalance(node);

    if (balance > 1 && key.prefix < node->left->key.prefix)
        return rightRotate(node);
 
    // Right Right Case
    if (balance < -1 && key.prefix > node->right->key.prefix)
        return leftRotate(node);
 
    // Left Right Case
    if (balance > 1 && key.prefix > node->left->key.prefix)
    {
        node->left =  leftRotate(node->left);
        return rightRotate(node);
    }
 
    // Right Left Case
    if (balance < -1 && key.prefix < node->right->key.prefix)
    {
        node->right = rightRotate(node->right);
        return leftRotate(node);
    }
 
    /* return the (unchanged) node pointer */
    return node;
}
struct bst_node* search(struct bst_node* root, uint32_t key)
{
    // Base Cases: root is null or key is present at root
    if (root == NULL || root->key.prefix == key)
       return root;
    
    // Key is greater than root's key
    if (root->key.prefix  < key)
       return search(root->right, key);
 
    // Key is smaller than root's key
    return search(root->left, key);
}

// Converts a string from format b4.b3.b2.b1 to a 32bit unsigned integer
// Eg: str_to_32b("192.1.4.0") = 3221292032
uint32_t str_to_32b(char* str) {
    uint8_t b1;
    uint8_t b2;
    uint8_t b3;
    uint8_t b4;
    sscanf(str, "%hhu.%hhu.%hhu.%hhu", &b4, &b3, &b2, &b1);
    return  (b4 << 24)  | 
            (b3 << 16)  |
            (b2 << 8)   | b1;
            
}

// Stores the input from file fd into rtable as an array of rtable_entry
void read_rtable(struct bst_node **rtable, FILE* fd) {
    // Count the number of entries by counting \n characters 


    // Allocate necessary memory for the entire routing table
    struct rtable_entry new_entry;
    rewind(fd);
    
    // Declarations used to populate the routing table
    char prefix_str[ADDR_MAXLEN];
    char nhop_str[ADDR_MAXLEN];
    char mask_str[ADDR_MAXLEN];
    char interf;
    // For each line in fd:
        // read formatted string into:  Prefix string, 
        //                              Next Hop string,
        //                              Mask string,
        //                              Interface char
        // add entry to rtable with each address converted to 32b uint
    
    int i;
    char* current_line = NULL;
    size_t line_limit = 0;
    for(i = 0; getline(&current_line, &line_limit, fd) > 0; i++) {
        sscanf(current_line, "%[0-9.] %[0-9.] %[0-9.] %hhd", prefix_str, \
                                                        nhop_str, \
                                                        mask_str, \
                                                        &interf);

        new_entry.prefix = str_to_32b(prefix_str);
        new_entry.next_hop = str_to_32b(nhop_str);
        new_entry.mask = str_to_32b(mask_str);
        new_entry.interface = interf;

        if(i == 0){
            *rtable = insert(*rtable, new_entry);
        }
            
        else 
            *rtable = insert(*rtable, new_entry);
        }

}

struct rtable_entry* get_best_route(uint32_t dest_ip, struct bst_node* rtable) {
	
    uint32_t mask;
    mask = 0xFFFFFFFF;
    struct bst_node* found = NULL;
    while(mask != 0){
        found = search(rtable, dest_ip & mask);

        if(found != NULL)
            return &found->key;

        mask = mask << 1;
        
    }

	return NULL;
}
struct arp_entry* get_arp(uint32_t dest_ip, struct arp_entry* arp_tb, int arp_t_size) {
    printf("LOOKING UP %x\n", dest_ip);
    for (int i = 0; i < arp_t_size; i++) {
        if(arp_tb[i].ip == dest_ip) {
            return &arp_tb[i];
        }
    }
    return NULL;
}

// Add a new ARP entry to the ARP table, return the new dimension of the ARP table
int add_to_arptable(struct arp_entry* arp_tb, struct arp_entry* new_arp, int arp_tb_size) {
    arp_tb[arp_tb_size] = *new_arp;

    // DEBUG
    // printf("ADDED ARP MAC: %x:%x:%x:%x:%x:%x\n", arp_tb[arp_tb_size].mac[0], arp_tb[arp_tb_size].mac[1], arp_tb[arp_tb_size].mac[2], arp_tb[arp_tb_size].mac[3], arp_tb[arp_tb_size].mac[4], arp_tb[arp_tb_size].mac[5]);
    // printf("ADDED ARP IP : %x\n", arp_tb[arp_tb_size].ip);
    return arp_tb_size + 1;


}
void preOrder(struct bst_node *root)
{
    if(root != NULL)
    {
        preOrder(root->left);
        printf("%d ", root->key.interface);
        
        preOrder(root->right);
    }
}
int main(int argc, char *argv[])
{

	packet m;
	int rc;
    char buf[20];
    // Open table input file and create routing table
    FILE* fd;
    fd = fopen(argv[1], "r");
    DIE(fd <= 0, "Failed to open file");

    // Routing table init
    struct bst_node* rtable = NULL;
    read_rtable(&rtable, fd);
    // ARP table init
    struct arp_entry* arptable = NULL;
    int arptable_size;
    // Size initially set to zero, future entries will increase it
    arptable_size = 0;
    arptable = malloc(sizeof(struct arp_entry) * ARPT_CAP);

    queue routerQueue;
    routerQueue = queue_create();

    init(argc - 2, argv + 2);
    
	while (1) {
        
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
        struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
        struct rtable_entry* best_route;
        
        // TODO: CHECK IF PACKAGE IS OF TYPE ICMP ECHO REQUEST
        struct icmphdr * icmp_header;
        icmp_header = parse_icmp(m.payload);

        if(icmp_header != NULL) {
            if(ntohl(ip_hdr->daddr) == str_to_32b(get_interface_ip(m.interface)) && icmp_header->type == ICMP_ECHO){
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
                get_interface_mac(m.interface, eth_hdr->ether_shost);
                send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, ICMP_ECHOREPLY, 0, m.interface, icmp_header->un.echo.id, icmp_header->un.echo.sequence);
                continue;
            }
                
        }
        // TODO: CHECK IF PACKAGE IS OF TYPE ARP
        struct arp_header *arp_hdr;
        arp_hdr = parse_arp(m.payload);
        // If ARP packet was meant for this router, send ARP reply
        if(arp_hdr != NULL) {
            // Check for match on each router interface
            // And send reply if packet was meant for this router
            for (int j = 0; j < ROUTER_NUM_INTERFACES; j++)
            {   
                // Check if the target was a router interface
                if(ntohl(arp_hdr->tpa) == str_to_32b(get_interface_ip(j))){
                    // If ARP has type REQUEST send this router's MAC
                    if(ntohs(arp_hdr->op) == ARPOP_REQUEST){
                        printf("GOT ARP REQUEST FROM: %s\n", inet_ntop(AF_INET, &arp_hdr->spa, buf, 20));
                        // Send ARP REPLY from this interface
                        // Set destination mac address to sender
                        memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
                        // Add the MAC of this interface to eth_header as source
                        get_interface_mac(j, eth_hdr->ether_shost);
                        eth_hdr->ether_type = htons(ETHERTYPE_ARP);
                        send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
                        printf("SENT ARP REPLY TO: %s\n", inet_ntop(AF_INET, &arp_hdr->spa, buf, 20));
                        break;
                    } else if(ntohs(arp_hdr->op) == ARPOP_REPLY) {

                        if(get_arp(ntohl(arp_hdr->spa), arptable, arptable_size) != NULL){
                            continue;
                        }
                        printf("GOT ARP REPLY FROM: %s\n", inet_ntop(AF_INET, &arp_hdr->spa, buf, 20));
                        // If ARP has type REPLY there exists a packet in queue to be sent
                        // Create a new ARP entry, populate and add it to the ARP table
                        struct arp_entry* new_arp = malloc(sizeof(struct arp_entry));
                        new_arp->ip = ntohl(arp_hdr->spa);
                        memcpy(new_arp->mac, arp_hdr->sha, 6);
                        arptable_size = add_to_arptable(arptable, new_arp, arptable_size);

                        // Pull original packet from queue
                        packet* original;
                        original = (packet*) queue_deq(routerQueue);

                        struct ether_header *orig_eth_hdr = (struct ether_header *) original->payload;
                        struct iphdr *orig_ip_hdr = (struct iphdr *)(original->payload + sizeof(struct ether_header));

                        // Checksum was already verified, last step is to populate the target MAC and send
                        best_route = get_best_route(ntohl(orig_ip_hdr->daddr), rtable);
                        memcpy(orig_eth_hdr->ether_dhost, new_arp->mac, 6);                        
                        get_interface_mac(best_route->interface, orig_eth_hdr->ether_shost);
                        send_packet(best_route->interface, original);
                        free(new_arp);
                        break;
                    }
                }
            }
            continue;
        } 

        // TODO: CHECK CHECKSUM
        if(ip_checksum(ip_hdr,sizeof(struct iphdr))){
            printf("Invalid Checksum\n");
            continue;
        }
        //http://www.firewall.cx/networking-topics/protocols/icmp-protocol/156-icmp-time-exceeded.html#:~:text=The%20ICMP%20%2D%20Time%20exceeded%20message%20is%20generated%20when%20the%20gateway,and%20therefore%20must%20be%20discarded.
        // TODO: CHECK TTL
        if(ip_hdr->ttl <= 1){
            printf("TTL expired\n");
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
            get_interface_mac(m.interface, eth_hdr->ether_shost);
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, ICMP_TIME_EXCEEDED, 0, m.interface);
            continue;
        }
        //TODO: FIND BEST ROUTE OR SEND ICMP HOST UNREACHABLE
        best_route = get_best_route(ntohl(ip_hdr->daddr), rtable);
        if(best_route == NULL) {
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
            get_interface_mac(m.interface, eth_hdr->ether_shost);
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, ICMP_PORT_UNREACH, 0, m.interface);
            continue;
        }
       
        //TODO: UPDATE TTL
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
        //TODO: FIND MATCHING ARP FOR NEXT HOP
        struct arp_entry* arp;
        arp = get_arp(best_route->next_hop, arptable, arptable_size);
        uint32_t test;
        test = ntohl(best_route->next_hop);
        // If arp is null, the arp table returned no results and an ARP request must be sent
        if (arp == NULL) {
            printf("NO MAC FOUND FOR %s IN ARP TABLE\n", inet_ntop(AF_INET, &test, buf, 20));
            printf("SENDING ARP REQUEST TO: %s FROM %s \n", inet_ntop(AF_INET, &test, buf, 20), get_interface_ip(best_route->interface));
            //TODO: IF NO MATCHING ARP FOUND ADD PACKET TO Q AND SEND REQUEST
            packet queuePacket = m;
            queue_enq(routerQueue, &queuePacket);
            // Generate new ethernet header
            // source ether addr set to interface MAC
            // destination set to broadcast MAC FF:FF:..:FF
            // type set to ETHERTYPE_ARP

            get_interface_mac(best_route->interface, eth_hdr->ether_shost);
            memset(eth_hdr->ether_dhost, 0xFF, 6);
            eth_hdr->ether_type = htons(ETHERTYPE_ARP);

            // Send the ARP request
            send_arp(htonl(best_route->next_hop), htonl(str_to_32b(get_interface_ip(best_route->interface))), eth_hdr, best_route->interface, htons(ARPOP_REQUEST));
            continue;
        }

        memcpy(eth_hdr->ether_dhost, arp->mac, 6);
        get_interface_mac(best_route->interface, eth_hdr->ether_shost);
        //TODO: FORWARD PACKET TO BEST ROUTE
        send_packet(best_route->interface, &m);

    }

    free(arptable);
    free(rtable);
}

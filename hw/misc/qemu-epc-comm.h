#ifndef QEMU_EPC_COMM_H
#define QEMU_EPC_COMM_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"

#define QEMU_EPC_SOCK_PATH "/tmp/qemu-epc.sock"

enum QEMU_EPC_MSG_TYPE {
    QEMU_EPC_MSG_TYPE_VER,
    QEMU_EPC_MSG_TYPE_PASS_FD,
    QEMU_EPC_MSG_TYPE_REQ_BAR,
    QEMU_EPC_MSG_TYPE_IRQ_INFO,
    QEMU_EPC_MSG_TYPE_TLP,
};

struct qemu_epc_msg_hdr {
    uint8_t type;
    union {
        struct {
            uint8_t reserved0;
            uint16_t reserved1;
        };
        struct {
            uint8_t idx;
            uint16_t reserved;
        } bar;
    };
} __attribute__((packed));

#define QEMU_EPC_PROTOCOL_VER 0x00000001

int qemu_epc_comm_start_server(int *srv_fd);
void qemu_epc_comm_shutdown_server(int clt_fd, int srv_fd);
int qemu_epc_comm_recv_msg(int fd, struct qemu_epc_msg_hdr *hdr);

int qemu_epc_comm_check_protcol_ver(int fd);
int qemu_epc_comm_resp_protocol_ver(int fd);
int qemu_epc_comm_pass_fd(int dfd, int fd);
int qemu_epc_comm_recv_fd(int rfd);

struct pci_bar {
    uint64_t phys_addr;
    uint64_t size;
    uint8_t flags;
} __attribute__((packed));

int qemu_epc_comm_req_bar(int fd, int idx, struct pci_bar *bar);
int qemu_epc_comm_resp_bar(int fd, struct pci_bar *bar);

int qemu_epc_comm_req_irq_info(int fd, uint8_t *int_pin);
int qemu_epc_comm_resp_irq_info(int fd, uint8_t int_pin);

#define PCI_TLP_TYPE_MR     0b00000000
#define PCI_TLP_TYPE_MRL    0b00000001
#define PCI_TLP_TYPE_MW     0b01000000
#define PCI_TLP_TYPE_IOR    0b00000010
#define PCI_TLP_TYPE_IOW    0b01000010
#define PCI_TLP_TYPE_CR0    0b00000100
#define PCI_TLP_TYPE_CW0    0b01000100
#define PCI_TLP_TYPE_CR1    0b00000101
#define PCI_TLP_TYPE_CW1    0b01000101
#define PCI_TLP_TYPE_MSG    0b00110000
#define PCI_TLP_TYPE_MSGD   0b01110000
#define PCI_TLP_TYPE_CPL    0b00001010
#define PCI_TLP_TYPE_CPLD   0b01001010
#define PCI_TLP_TYPE_CPLLK  0b00001011
#define PCI_TLP_TYPE_CPLDLK 0b01001011
#define PCI_TLP_TYPE_FETCHADD   0b01001101
#define PCI_TLP_TYPE_CAS    0b01001110
#define PCI_TLP_TYPE_LPRFX  0b10000000
#define PCI_TLP_TYPE_EPRFX  0b10010000

struct pci_tlp_hdr_dw0 {
    uint8_t fmt_type;
    uint8_t tmp;
    uint8_t tmp2:6;
    uint16_t length:10;
} __attribute__((packed));

struct pci_tlp_config {
    struct pci_tlp_hdr_dw0 dw0;
    uint32_t dw1;
    struct {
        uint8_t bus_num;
        uint8_t dev_num:4;
        uint8_t func_num:4;
        uint8_t rsv1:4;
        uint8_t ext_reg_num:4;
        uint8_t reg_num:6;
        uint8_t rsv0:2;
    } __attribute__((packed)) dw2;
} __attribute__((packed));

struct pci_tlp_comp {
    struct pci_tlp_hdr_dw0 dw0;
    uint32_t dw1, dw2;
} __attribute__((packed));

struct pci_tlp_msg {
    struct pci_tlp_hdr_dw0 dw0;
    struct {
        uint16_t req_id;
        uint8_t tag;
        uint8_t msg_code;
    } __attribute__((packed)) dw1;
    uint32_t dw23[2];
} __attribute__((packed));

struct pci_tlp_mem {
    struct pci_tlp_hdr_dw0 dw0;
    uint32_t dw1;
    struct {
        uint32_t haddr;
        uint32_t laddr;
    } __attribute__((packed)) dw23;
} __attribute__((packed));

int qemu_epc_comm_get_pci_offset_from_tlp(struct pci_tlp_config *tlp,
        uint32_t *offset);

int qemu_epc_comm_recv_tlp(int fd, uint32_t hdr[4]);
int qemu_epc_comm_config_read(int fd, size_t offset, uint32_t *data);
int qemu_epc_comm_comp_with_data(int fd, void *buf, size_t length);

hwaddr qemu_epc_comm_get_pci_addr_from_tlp(struct pci_tlp_mem *tlp);
size_t qemu_epc_comm_tlp_data_length(struct pci_tlp_hdr_dw0 *dw0);

int qemu_epc_comm_bar_read(int fd, int idx, hwaddr offset, void *data,
        size_t length);
int qemu_epc_comm_bar_write(int fd, int idx, hwaddr offset, void *data,
        size_t length);
int qemu_epc_comm_mem_read(int fd, hwaddr pci, void *data, size_t length);
int qemu_epc_comm_mem_write(int fd, hwaddr pci, void *data, size_t length);

int qemu_epc_comm_load_data(int fd, void *dest, size_t length);

#define PCI_TLP_MSG_CODE_ASRT_INTA 0b00100000
#define PCI_TLP_MSG_CODE_ASRT_INTB 0b00100001
#define PCI_TLP_MSG_CODE_ASRT_INTC 0b00100010
#define PCI_TLP_MSG_CODE_ASRT_INTD 0b00100011
#define PCI_TLP_MSG_CODE_DASRT_INTA 0b00100100
#define PCI_TLP_MSG_CODE_DASRT_INTB 0b00100101
#define PCI_TLP_MSG_CODE_DASRT_INTC 0b00100110
#define PCI_TLP_MSG_CODE_DASRT_INTD 0b00100111

int qemu_epc_comm_raise_irq(int fd, int intn);

enum PCI_TLP_IRQ_NUM {
    PCI_TLP_IRQ_INVALID,
    PCI_TLP_IRQ_INTA,
    PCI_TLP_IRQ_INTB,
    PCI_TLP_IRQ_INTC,
    PCI_TLP_IRQ_INTD,
};

enum PCI_TLP_IRQ_NUM qemu_epc_comm_irqn_from_tlp(struct pci_tlp_msg *tlp);

#endif /* QEMU_EPC_COMM_H */

/*
 * A implementation of protocol between QEMU PCI Endpoint
 * Controller(EPC) and Endpoint device emulation.
 *
 * The endpoint device emulator works as a server and, the QEMU PCI EPC connect
 * to them.
 */

#include "qemu-epc-comm.h"
#include "qemu/log.h"

int qemu_epc_comm_start_server(int *srv_fd)
{
    struct sockaddr_un sun;
    socklen_t socklen;
    int err;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, QEMU_EPC_SOCK_PATH);

    err = bind(fd, (const struct sockaddr *)&sun, sizeof(sun));
    if (err == -1) {
        return -1;
    }

    err = listen(fd, 1);
    if (err == -1) {
        return -1;
    }

    *srv_fd = fd;

    socklen = sizeof(sun);

    return accept(fd, (struct sockaddr *)&sun, &socklen);
}

void qemu_epc_comm_shutdown_server(int clt_fd, int srv_fd)
{
    close(clt_fd);
    close(srv_fd);
}

int qemu_epc_comm_recv_msg(int fd, struct qemu_epc_msg_hdr *hdr)
{
    ssize_t size;

    size = recv(fd, hdr, sizeof(*hdr), 0);
    if (size != sizeof(*hdr)) {
        qemu_log("%s: invalid: %ld != %ld\n", __func__, size, sizeof(*hdr));
        return -1;
    }

    return 0;
}

int qemu_epc_comm_check_protcol_ver(int fd)
{
    struct qemu_epc_msg_hdr emsg = {
        .type = QEMU_EPC_MSG_TYPE_VER,
    };
    ssize_t size;
    uint32_t ver;

    size = send(fd, &emsg, sizeof(emsg), 0);
    if (size != sizeof(emsg)) {
        return -1;
    }

    size = recv(fd, &ver, sizeof(ver), 0);
    if (size != sizeof(ver)) {
        return -1;
    }

    return !(ver == QEMU_EPC_PROTOCOL_VER);
}

int qemu_epc_comm_resp_protocol_ver(int fd)
{
    uint32_t ver = QEMU_EPC_PROTOCOL_VER;
    ssize_t size;

    size = send(fd, &ver, sizeof(ver), 0);

    return size != sizeof(ver);
}

int qemu_epc_comm_pass_fd(int dfd, int fd)
{
    struct msghdr msg = { 0 };
    char buf[CMSG_SPACE(sizeof(fd))] = {0};
    ssize_t size;
    /*
     * In order to send the ancillary data, we have to send payload at least on
     * byte.
     */
    char iobuf[1];
    struct iovec io = { .iov_base = iobuf, .iov_len = sizeof(iobuf) };

    struct qemu_epc_msg_hdr emsg = {
        .type = QEMU_EPC_MSG_TYPE_PASS_FD,
    };

    size = send(dfd, &emsg, sizeof(emsg), 0);
    if (size != sizeof(emsg)) {
        return -1;
    }

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

    *((typeof(fd) *) CMSG_DATA(cmsg)) = fd;

    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    size = sendmsg(dfd, &msg, 0);

    return !(size == sizeof(iobuf));
}

int qemu_epc_comm_recv_fd(int rfd)
{
    ssize_t size;
    char inbuf[1];
    struct iovec iov = {inbuf, sizeof(inbuf)};
    char cmsg[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg,
        .msg_controllen = sizeof(cmsg),
        .msg_flags = 0
    };
    struct cmsghdr *cmsghdr;

    size = recvmsg(rfd, &msg, 0);
    if (size < 0) {
        return -1;
    }

    cmsghdr = CMSG_FIRSTHDR(&msg);

    return *(int *)CMSG_DATA(cmsghdr);
}

int qemu_epc_comm_req_bar(int fd, int idx, struct pci_bar *bar)
{
    struct qemu_epc_msg_hdr emsg = {
        .type = QEMU_EPC_MSG_TYPE_REQ_BAR,
        .bar.idx = idx,
    };
    ssize_t size;

    size = send(fd, &emsg, sizeof(emsg), 0);
    if (size != sizeof(emsg)) {
        return -1;
    }

    size = recv(fd, bar, sizeof(*bar), 0);
    if (size != sizeof(*bar)) {
        return -1;
    }

    return 0;
}

int qemu_epc_comm_resp_bar(int fd, struct pci_bar *bar)
{
    ssize_t size;

    size = send(fd, bar, sizeof(*bar), 0);
    if (size != sizeof(*bar)) {
        return -1;
    }

    return 0;
};

int qemu_epc_comm_comp_with_data(int fd, void *buf, size_t length)
{
    struct pci_tlp_comp tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_CPLD,
        .dw0.length = length >> 2,
    };
    ssize_t size;

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        return -1;
    }

    size = send(fd, buf, length, 0);
    if (size != length) {
        return -1;
    }

    return 0;
}

static int _qemu_epc_comm_recv_comp_with_data(int fd, void *buf, size_t length)
{
    struct pci_tlp_comp tlp;
    ssize_t size;

    size = recv(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        return -1;
    }

    if (tlp.dw0.fmt_type != PCI_TLP_TYPE_CPLD) {
        return -1;
    }

    size = recv(fd, buf, length, 0);
    if (size != length) {
        return -1;
    }

    return 0;
}

int qemu_epc_comm_recv_tlp(int fd, uint32_t hdr[4])
{
    ssize_t size, rvsize;
    void *ptr;
    struct pci_tlp_hdr_dw0 *dw0;
    size = recv(fd, &hdr[0], sizeof(hdr[0]), 0);
    if (size != sizeof(hdr[0])) {
        return -1;
    }

    dw0 = (struct pci_tlp_hdr_dw0 *)&hdr[0];
    switch (dw0->fmt_type) {
    case PCI_TLP_TYPE_CR0:
        size = recv(fd, &hdr[1], sizeof(hdr[1]) * 2, 0);
        if (size != sizeof(hdr[1]) * 2) {
            qemu_log("%s:%d receive err 0x%lx != 0x%lx\n", __func__, __LINE__,
                     size, sizeof(hdr[1]) * 2);
            return -1;
        }
        break;
    case PCI_TLP_TYPE_MW:
    case PCI_TLP_TYPE_MR:
    case PCI_TLP_TYPE_MSG:
        rvsize = sizeof(hdr[1]) * 3;
        ptr = &hdr[1];
        while (1) {
            size = recv(fd, ptr, rvsize, 0);
            if (size < 0) {
                qemu_log("%s:%d receive err: %ld\n", __func__, __LINE__, size);
                return -1;
            }
            rvsize -= size;
            if (rvsize == 0) {
                break;
            }

            ptr += size;
        }
        break;
    default:
        qemu_log("not supported: %d\n", dw0->fmt_type);
        return -2;
    }

    return 0;
}

int qemu_epc_comm_get_pci_offset_from_tlp(struct pci_tlp_config *tlp,
                                          uint32_t *offset)
{
    uint32_t off;

    off = (uint32_t)tlp->dw2.reg_num << 2;
    off |= (uint32_t)tlp->dw2.ext_reg_num << 8;

    *offset = off;

    return 0;
}

int qemu_epc_comm_config_read(int fd, size_t offset, uint32_t *data)
{
    ssize_t size;
    struct qemu_epc_msg_hdr emsg = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
    };

    struct pci_tlp_config tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_CR0,
        .dw0.length = 1,
        .dw2.reg_num = (offset & 0xfc) >> 2,
        .dw2.ext_reg_num = (offset & 0xf00) >> 8,
    };

    size = send(fd, &emsg, sizeof(emsg), 0);
    if (size != sizeof(emsg)) {
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        return -1;
    }

    return _qemu_epc_comm_recv_comp_with_data(fd, data, sizeof(*data));
}


size_t qemu_epc_comm_tlp_data_length(struct pci_tlp_hdr_dw0 *dw0)
{
    return (size_t)dw0->length << 2;
}

int qemu_epc_comm_bar_read(int fd, int idx, hwaddr offset, void *data,
                           size_t length)
{
    struct qemu_epc_msg_hdr mhdr = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
        .bar.idx = idx,
    };
    struct pci_tlp_mem tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_MR,
        .dw0.length = length >> 2,
        .dw23.laddr = (uint32_t)offset,
        .dw23.haddr = offset >> 32,
    };
    ssize_t size;

    size = send(fd, &mhdr, sizeof(mhdr), 0);
    if (size != sizeof(mhdr)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    return _qemu_epc_comm_recv_comp_with_data(fd, data, length);
}

hwaddr qemu_epc_comm_get_pci_addr_from_tlp(struct pci_tlp_mem *tlp)
{
    return  (hwaddr)tlp->dw23.haddr << 32 | (hwaddr)tlp->dw23.laddr;
}

int qemu_epc_comm_bar_write(int fd, int idx, hwaddr offset, void *data,
                            size_t length)
{
    struct qemu_epc_msg_hdr mhdr = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
        .bar.idx = idx,
    };
    struct pci_tlp_mem tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_MW,
        .dw0.length = length >> 2,
        .dw23.laddr = (uint32_t)offset,
        .dw23.haddr = offset >> 32,
    };
    ssize_t size;

    size = send(fd, &mhdr, sizeof(mhdr), 0);
    if (size != sizeof(mhdr)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, data, length, 0);
    if (size != length) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int qemu_epc_comm_mem_read(int fd, hwaddr pci, void *data, size_t length)
{
    struct qemu_epc_msg_hdr mhdr = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
    };
    struct pci_tlp_mem tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_MR,
        .dw0.length = length >> 2,
        .dw23.laddr = (uint32_t)pci,
        .dw23.haddr = pci >> 32,
    };
    ssize_t size;

    size = send(fd, &mhdr, sizeof(mhdr), 0);
    if (size != sizeof(mhdr)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        return -1;
    }

    return _qemu_epc_comm_recv_comp_with_data(fd, data, length);
}

int qemu_epc_comm_mem_write(int fd, hwaddr pci, void *data, size_t length)
{
    struct qemu_epc_msg_hdr mhdr = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
    };
    struct pci_tlp_mem tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_MW,
        .dw0.length = length >> 2,
        .dw23.laddr = (uint32_t)pci,
        .dw23.haddr = pci >> 32,
    };
    ssize_t size;

    size = send(fd, &mhdr, sizeof(mhdr), 0);
    if (size != sizeof(mhdr)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, data, length, 0);
    if (size != length) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int qemu_epc_comm_load_data(int fd, void *dest, size_t length)
{
    ssize_t size;

    size = recv(fd, dest, length, 0);
    if (size != length) {
        return -1;
    }

    return 0;
}

int qemu_epc_comm_raise_irq(int fd, int intn)
{
    struct qemu_epc_msg_hdr mhdr = {
        .type = QEMU_EPC_MSG_TYPE_TLP,
    };
    struct pci_tlp_msg tlp = {
        .dw0.fmt_type = PCI_TLP_TYPE_MSG,
    };
    ssize_t size;

    switch (intn) {
    case 0:
        tlp.dw1.msg_code = PCI_TLP_MSG_CODE_ASRT_INTA;
        break;
    case 1:
        tlp.dw1.msg_code = PCI_TLP_MSG_CODE_ASRT_INTB;
        break;
    case 2:
        tlp.dw1.msg_code = PCI_TLP_MSG_CODE_ASRT_INTC;
        break;
    case 3:
        tlp.dw1.msg_code = PCI_TLP_MSG_CODE_ASRT_INTD;
        break;
    default:
        qemu_log("invalid irq number found: %d\n", intn);
        return -1;
    }

    size = send(fd, &mhdr, sizeof(mhdr), 0);
    if (size != sizeof(mhdr)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    size = send(fd, &tlp, sizeof(tlp), 0);
    if (size != sizeof(tlp)) {
        qemu_log("%s:%d\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

enum PCI_TLP_IRQ_NUM qemu_epc_comm_irqn_from_tlp(struct pci_tlp_msg *tlp)
{
    switch (tlp->dw1.msg_code) {
    case PCI_TLP_MSG_CODE_ASRT_INTA:
        return PCI_TLP_IRQ_INTA;
    case PCI_TLP_MSG_CODE_ASRT_INTB:
        return PCI_TLP_IRQ_INTB;
    case PCI_TLP_MSG_CODE_ASRT_INTC:
        return PCI_TLP_IRQ_INTC;
    case PCI_TLP_MSG_CODE_ASRT_INTD:
        return PCI_TLP_IRQ_INTD;
    default:
        return PCI_TLP_IRQ_INVALID;
    }
}

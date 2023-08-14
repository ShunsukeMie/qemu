/*
 * QEMU PCI Endpoint Controller device
 */

#include "qemu/osdep.h"
#include "qom/object.h"
#include "hw/pci/pci_device.h"

#include "qemu-epc-comm.h"

#define DEBUG_QEMU_EPC
#ifdef DEBUG_QEMU_EPC
#include "qemu/log.h"
#define qemu_epc_debug(...) qemu_log("QemuEPC: " __VA_ARGS__)
#else
#define qemu_epc_debug(...) do {} while (0)
#endif

#define QEMU_EPC_REVISON 0x00

struct QemuEPCState {
    /*< private >*/
    PCIDevice dev;

    /*< public >*/
    MemoryRegion ctrl_mr, pci_cfg_mr, bar_cfg_mr;
    MemoryRegion ob_window_mr;
    uint32_t ob_map_mask;
    uint32_t ob_idx;
    struct qemu_epc_ob_map {
        uint64_t phys;
        uint64_t pci;
        uint64_t size;
    } ob_map[32];

    QemuThread thread;

    int srv_fd, clt_fd;
    int req_fd;

    uint8_t pcie_cfg_space[PCIE_CONFIG_SPACE_SIZE];

    /* configuration for BAR */
    struct pci_bar bars[6];

    uint8_t bar_mask;
    uint8_t bar_no;
    uint8_t irq_type;
};

#define TYPE_QEMU_EPC "qemu-epc"

OBJECT_DECLARE_SIMPLE_TYPE(QemuEPCState, QEMU_EPC);

enum {
    QEMU_EPC_BAR_CTRL = 0,
    QEMU_EPC_BAR_PCI_CFG = 1,
    QEMU_EPC_BAR_BAR_CFG = 2,
    QEMU_EPC_BAR_OB_WINDOW = 3,
};

#define QEMU_EPC_OB_WINDOW_SIZE 0x100000
#define QEMU_EPC_NUM_OF_OB_MAPS 0x10

struct qemu_epc_ob_map_reg {
    uint64_t phys_dddr;
    uint64_t pci_addr;
    uint64_t size;
    uint64_t reserved;
} __attribute__((packed));

enum {
    QEMU_EPC_CTRL_OFF_START = 0x00,
    QEMU_EPC_CTRL_OFF_WIN_START = 0x8,
    QEMU_EPC_CTRL_OFF_WIN_SIZE = 0x10,
    QEMU_EPC_CTRL_OFF_IRQ_TYPE = 0x18,
    QEMU_EPC_CTRL_OFF_IRQ_NUM = 0x1c,
    QEMU_EPC_CTRL_OFF_OB_MAP_MASK = 0x20,
    QEMU_EPC_CTRL_OFF_OB_IDX = 0x24,
    QEMU_EPC_CTRL_OFF_OB_MAP_PHYS = 0x28,
    QEMU_EPC_CTRL_OFF_OB_MAP_PCI = 0x30,
    QEMU_EPC_CTRL_OFF_OB_MAP_SIZE = 0x38,

    QEMU_EPC_CTRL_SIZE = QEMU_EPC_CTRL_OFF_OB_MAP_SIZE + sizeof(uint64_t)
};

static uint64_t qemu_epc_mmio_ctrl_read(void *opaque, hwaddr addr,
                                        unsigned size)
{
    QemuEPCState *s = opaque;

    qemu_epc_debug("CTRL read: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_CTRL_OFF_WIN_START:
        return s->ob_window_mr.addr;
    case QEMU_EPC_CTRL_OFF_WIN_START + sizeof(uint32_t):
        return s->ob_window_mr.addr >> 32;
    case QEMU_EPC_CTRL_OFF_WIN_SIZE:
        return 0x100000;
    case QEMU_EPC_CTRL_OFF_WIN_SIZE + sizeof(uint32_t):
        return 0;
    case QEMU_EPC_CTRL_OFF_OB_MAP_MASK:
        return s->ob_map_mask;
    default:
        qemu_epc_debug("unexpected read found: %ld\n", addr);
    }

    return 0;
}

static int qemu_epc_handle_tlp_mr(QemuEPCState *s, int fd,
                                  struct pci_tlp_mem *tlp,
                                  struct qemu_epc_msg_hdr *mhdr)
{
    int err;
    size_t offset = qemu_epc_comm_get_pci_addr_from_tlp(tlp);
    int idx = mhdr->bar.idx;
    hwaddr addr;
    size_t length = qemu_epc_comm_tlp_data_length(&tlp->dw0);
    void *buf;

    addr = s->bars[idx].phys_addr + offset;
    qemu_log("idx 0x%x, addr 0x%lx, offset 0x%lx, len 0x%lx\n", idx, addr,
             offset, length);

    buf = pci_dma_map(&s->dev, addr, &length, DMA_DIRECTION_TO_DEVICE);

    qemu_log("%s: 0x%x\n", __func__, *(uint32_t *)buf);

    err = qemu_epc_comm_comp_with_data(fd, buf, length);

    pci_dma_unmap(&s->dev, buf, length, DMA_DIRECTION_TO_DEVICE, length);

    return err;
}

static int qemu_epc_handle_tlp_mw(QemuEPCState *s, int fd,
                                  struct pci_tlp_mem *tlp,
                                  struct qemu_epc_msg_hdr *mhdr)
{
    int err;
    hwaddr addr;
    void *buf;
    int idx = mhdr->bar.idx;
    size_t offset = qemu_epc_comm_get_pci_addr_from_tlp(tlp);
    size_t length = qemu_epc_comm_tlp_data_length(&tlp->dw0);

    addr = s->bars[idx].phys_addr + offset;

    qemu_log("%s:%d addr 0x%lx, offset 0x%lx, len 0x%lx\n", __func__, __LINE__,
             addr, offset, length);
    buf = pci_dma_map(&s->dev, addr, &length, DMA_DIRECTION_FROM_DEVICE);

    err = qemu_epc_comm_load_data(fd, buf, length);

    pci_dma_unmap(&s->dev, buf, length, DMA_DIRECTION_FROM_DEVICE, length);

    return err;
}

static int qemu_epc_handle_tlp_cr0(QemuEPCState *s, int fd,
                                   struct pci_tlp_config *tlp)
{
    int err;
    uint32_t offset;

    err = qemu_epc_comm_get_pci_offset_from_tlp(tlp, &offset);
    if (err) {
        qemu_epc_debug("%s:%d %d\n", __func__, __LINE__, err);
        return err;
    }

    if (offset + 4 >= PCIE_CONFIG_SPACE_SIZE) {
        return err;
    }

    qemu_epc_debug("%s:%d off 0x%x, val 0x%x\n", __func__, __LINE__, offset,
                   *(uint32_t *)(&s->pcie_cfg_space[offset]));

    /* The size of TLP config read is fixed to 4. */
    return qemu_epc_comm_comp_with_data(fd, &s->pcie_cfg_space[offset], 4);
}

static int qemu_epc_hande_tlp(QemuEPCState *s, int fd,
                              struct qemu_epc_msg_hdr *mhdr)
{
    int err;
    uint32_t tlp_hdr[4];
    struct pci_tlp_hdr_dw0 *dw0;

    err = qemu_epc_comm_recv_tlp(fd, tlp_hdr);
    if (err) {
        qemu_epc_debug("%s:%d %d\n", __func__, __LINE__, err);
        return -1;
    }

    dw0 = (struct pci_tlp_hdr_dw0 *)&tlp_hdr[0];

    switch (dw0->fmt_type) {
    case PCI_TLP_TYPE_MR:
        err = qemu_epc_handle_tlp_mr(s, fd, (struct pci_tlp_mem *)tlp_hdr,
                                     mhdr);
        if (err) {
            qemu_epc_debug("%s:%d %d\n", __func__, __LINE__, err);
            return -1;
        }
        break;
    case PCI_TLP_TYPE_MW:
        err = qemu_epc_handle_tlp_mw(s, fd, (struct pci_tlp_mem *)tlp_hdr,
                                     mhdr);
        if (err) {
            qemu_epc_debug("%s:%d %d\n", __func__, __LINE__, err);
            return -1;
        }
        break;
    case PCI_TLP_TYPE_CR0:
        err = qemu_epc_handle_tlp_cr0(s, fd,
                                      (struct pci_tlp_config *)tlp_hdr);
        if (err) {
            qemu_epc_debug("%s:%d %d\n", __func__, __LINE__, err);
            return -1;
        }
        break;
    default:
        qemu_epc_debug("The fmt type[0x%x] is not supported\n",
                       dw0->fmt_type);
        return -1;
    }

    return 0;
}

static int qemu_epc_handle_req_bar(QemuEPCState *s, int fd, int idx)
{
    if (idx > 5) {
        return -1;
    }

    if (s->bar_mask & 1 << idx) {
        return qemu_epc_comm_resp_bar(fd, &s->bars[idx]);
    } else {
        struct pci_bar bar = {};
        return qemu_epc_comm_resp_bar(fd, &bar);
    }
}

static void *qemu_epc_thread(void *opaque)
{
    QemuEPCState *s = opaque;
    int err;
    int fd;
    struct qemu_epc_msg_hdr hdr;

    fd = qemu_epc_comm_start_server(&s->srv_fd);
    if (fd < 0) {
        qemu_epc_debug("failed to start server\n");
        return NULL;
    }

    while (true) {
        err = qemu_epc_comm_recv_msg(fd, &hdr);
        if (err) {
            qemu_epc_debug("failed to receive message from client\n");
            goto done;
        }

        switch (hdr.type) {
        case QEMU_EPC_MSG_TYPE_VER:
            err = qemu_epc_comm_resp_protocol_ver(fd);
            if (err) {
                qemu_epc_debug("Failed to send protocol version\n");
                goto done;
            }
            break;
        case QEMU_EPC_MSG_TYPE_PASS_FD:
            s->req_fd = qemu_epc_comm_recv_fd(fd);
            if (s->req_fd < 0) {
                qemu_epc_debug("Failed to receive a fd to request\n");
                goto done;
            }
            break;
        case QEMU_EPC_MSG_TYPE_REQ_BAR:
            err = qemu_epc_handle_req_bar(s, fd, hdr.bar.idx);
            if (err) {
                qemu_epc_debug("Failed to handle requesting bar info\n");
                goto done;
            }
            break;
        case QEMU_EPC_MSG_TYPE_TLP:
            err = qemu_epc_hande_tlp(s, fd, &hdr);
            if (err) {
                qemu_epc_debug("Failed to handle TLP\n");
                goto done;
            }
            break;
        default:
            qemu_epc_debug("receive unknown message type: %d\n", hdr.type);
            goto done;
        }

    }

done:
    qemu_epc_comm_shutdown_server(fd, s->srv_fd);

    return NULL;
}

static void qemu_epc_handle_ctrl_start(QemuEPCState *s, uint64_t val)
{
    qemu_thread_create(&s->thread, "qemu-epc", qemu_epc_thread, s,
                       QEMU_THREAD_JOINABLE);
}

static void qemu_epc_handle_ctl_irq(QemuEPCState *s, uint64_t val)
{
    int err;

    err = qemu_epc_comm_raise_irq(s->req_fd, val);
    if (err) {
        qemu_epc_debug("Failed to raise irq\n");
    }
}

static void qemu_epc_mmio_ctrl_write(void *opaque, hwaddr addr, uint64_t val,
                                     unsigned size)
{
    QemuEPCState *s = opaque;
    uint64_t *tmp;

    qemu_epc_debug("CTRL write: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_CTRL_OFF_START:
        qemu_epc_handle_ctrl_start(s, val);
        return;
    case QEMU_EPC_CTRL_OFF_IRQ_TYPE:
        s->irq_type = val;
        break;
    case QEMU_EPC_CTRL_OFF_IRQ_NUM:
        qemu_epc_handle_ctl_irq(s, val);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_MASK:
        s->ob_map_mask = val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_IDX:
        s->ob_idx = val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PHYS:
        tmp = &s->ob_map[s->ob_idx].phys;
        *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PHYS + sizeof(uint32_t):
        tmp = &s->ob_map[s->ob_idx].phys;
        *tmp = (*tmp & 0xffffffff) | (val << 32);
        qemu_epc_debug("ob map phys: %d: 0x%lx\n", s->ob_idx, *tmp);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PCI:
        tmp = &s->ob_map[s->ob_idx].pci;
        *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PCI + sizeof(uint32_t):
        tmp = &s->ob_map[s->ob_idx].pci;
        *tmp = (*tmp & 0xffffffff) | (val << 32);
        qemu_epc_debug("ob map pci: %d: 0x%lx\n", s->ob_idx, *tmp);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_SIZE:
        tmp = &s->ob_map[s->ob_idx].size;
        *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_SIZE + sizeof(uint32_t):
        tmp = &s->ob_map[s->ob_idx].size;
        *tmp = (*tmp & 0xffffffff) | (val << 32);
        qemu_epc_debug("ob map size: %d: 0x%lx\n", s->ob_idx, *tmp);
        break;
    default:
        qemu_epc_debug("CTRL write: invalid address 0x%lx\n", addr);
    }
}

static const MemoryRegionOps qemu_epc_mmio_ctrl_ops = {
    .read = qemu_epc_mmio_ctrl_read,
    .write = qemu_epc_mmio_ctrl_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

enum {
    QEMU_EPC_BAR_CFG_OFF_MASK = 0x00,
    QEMU_EPC_BAR_CFG_OFF_NUMBER = 0x01,
    QEMU_EPC_BAR_CFG_OFF_FLAGS = 0x02,
    QEMU_EPC_BAR_CFG_OFF_RSV = 0x04,
    QEMU_EPC_BAR_CFG_OFF_PHYS_ADDR = 0x08,
    QEMU_EPC_BAR_CFG_OFF_SIZE = 0x10,

    QEMU_EPC_BAR_CFG_SIZE = 0x18
};

static uint64_t qemu_epc_mmio_pci_cfg_read(void *opaque, hwaddr addr,
                                           unsigned size)
{
    uint64_t data;
    QemuEPCState *s = opaque;

    qemu_epc_debug("PCI cfg read: addr 0x%lx, size 0x%x\n", addr, size);

    if (addr + size > PCIE_CONFIG_SPACE_SIZE) {
        qemu_epc_debug("PCI cfg write: detect outbounds access: 0x%lx\n",
                       addr + size);
        return 0 ;
    }

    memcpy(&data, &s->pcie_cfg_space[addr], size);

    return data;
}

static void qemu_epc_mmio_pci_cfg_write(void *opaque, hwaddr addr, uint64_t val,
                                        unsigned size)
{
    QemuEPCState *s = opaque;

    qemu_epc_debug("PCI cfg write: addr 0x%lx, size 0x%x, val 0x%lx\n", addr,
                   size, val);

    if (addr + size > PCIE_CONFIG_SPACE_SIZE) {
        qemu_epc_debug("PCI cfg write: detect outbounds access: 0x%lx\n",
                       addr + size);
        return;
    }

    memcpy(&s->pcie_cfg_space[addr], &val, size);

    return;
}

static const MemoryRegionOps qemu_epc_mmio_pci_cfg_ops = {
    .read = qemu_epc_mmio_pci_cfg_read,
    .write = qemu_epc_mmio_pci_cfg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t qemu_epc_mmio_bar_cfg_read(void *opaque, hwaddr addr,
                                           unsigned size)
{
    QemuEPCState *s = opaque;

    qemu_epc_debug("BAR cfg read: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_BAR_CFG_OFF_MASK:
        return s->bar_mask;
    case QEMU_EPC_BAR_CFG_OFF_NUMBER:
        return s->bar_no;
    default:
        qemu_epc_debug("BAR cfg read: detects unexpected read: 0x%lx\n",
                       addr);
    }

    return 0;
}

static void qemu_epc_mmio_bar_cfg_write(void *opaque, hwaddr addr, uint64_t val,
                                        unsigned size)
{
    QemuEPCState *s = opaque;
    uint64_t tmp;

    qemu_epc_debug("BAR cfg write: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_BAR_CFG_OFF_MASK:
        s->bar_mask = (uint8_t)val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_NUMBER:
        s->bar_no = (uint8_t)val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_FLAGS:
        if (s->bar_no > 5) {
            qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
            break;
        }
        s->bars[s->bar_no].flags = (uint8_t)val;
        s->pcie_cfg_space[PCI_BASE_ADDRESS_0 + s->bar_no * sizeof(uint32_t)]
            = val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_PHYS_ADDR:
        if (s->bar_no > 5) {
            qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
            break;
        }
        if (size == sizeof(uint32_t)) {
            tmp = (s->bars[s->bar_no].phys_addr & ~0xffffffffUL) | val;
        } else if (size == sizeof(uint64_t)) {
            tmp = val;
        } else {
            qemu_epc_debug("BAR cfg write: write size is invalid\n");
            break;
        }
        s->bars[s->bar_no].phys_addr = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_PHYS_ADDR + sizeof(uint32_t):
        if (s->bar_no > 5) {
            qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
            break;
        }
        if (size != sizeof(uint32_t)) {
            qemu_epc_debug("BAR cfg write: write size is invalid\n");
            break;
        }
        tmp = (s->bars[s->bar_no].phys_addr & 0xffffffffUL) | (val << 32);
        s->bars[s->bar_no].phys_addr = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_SIZE:
        if (s->bar_no > 5) {
            qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
            break;
        }
        if (size == sizeof(uint32_t)) {
            tmp = (s->bars[s->bar_no].size & ~0xffffffffUL) | val;
        } else if (size == sizeof(uint64_t)) {
            tmp = val;
        } else {
            qemu_epc_debug("BAR cfg write: write size is invalid\n");
            break;
        }
        s->bars[s->bar_no].size = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_SIZE + sizeof(uint32_t):
        if (s->bar_no > 5) {
            qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
            break;
        }

        if (size != sizeof(uint32_t)) {
            qemu_epc_debug("BAR cfg write: write size is invalid\n");
            break;
        }
        tmp = (s->bars[s->bar_no].size & 0xffffffffUL) | (val << 32);
        s->bars[s->bar_no].size = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_RSV:
    default:
        qemu_epc_debug("BAR cfg write: Detect invalid address: 0x%lx\n",
                       addr);
    }
}

static const MemoryRegionOps qemu_epc_mmio_bar_cfg_ops = {
    .read = qemu_epc_mmio_bar_cfg_read,
    .write = qemu_epc_mmio_bar_cfg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static int qemu_epc_get_map_address(QemuEPCState *s, hwaddr phys, unsigned size,
                                    hwaddr *pci)
{
    for (int i = 0; i < 32; i++) {
        struct qemu_epc_ob_map *map = &s->ob_map[i];

        if (phys < map->phys && phys >= map->phys + map->size) {
            continue;
        }

        *pci = map->pci + phys - map->phys;
        return 0;
    }

    return -1;
}

static uint64_t qemu_epc_mmio_ob_window_read(void *opaque, hwaddr addr,
                                             unsigned size)
{
    QemuEPCState *s = opaque;
    hwaddr phys = s->ob_window_mr.addr + addr;
    hwaddr pci;
    int err;
    uint64_t data;

    qemu_epc_debug("OB windows read: addr 0x%lx, size 0x%x\n", addr, size);

    err = qemu_epc_get_map_address(s, phys, size, &pci);
    if (err) {
        qemu_epc_debug("detect invalid adress to read");
        return 0;
    }

    err = qemu_epc_comm_mem_read(s->req_fd, pci, &data, size);
    if (err) {
        qemu_epc_debug("failed to request read");
        return 0;
    }

    return data;
}

static void qemu_epc_mmio_ob_window_write(void *opaque, hwaddr addr,
                                          uint64_t val, unsigned size)
{
    QemuEPCState *s = opaque;
    hwaddr phys, pci;
    int err;

    qemu_epc_debug("OB windows write: addr 0x%lx, size 0x%x\n", addr, size);

    phys = s->ob_window_mr.addr + addr;

    err = qemu_epc_get_map_address(s, phys, size, &pci);
    if (err) {
        qemu_epc_debug("failed to walk outbounds map\n");
        return;
    }

    err = qemu_epc_comm_mem_write(s->req_fd, pci, &val, size);
    if (err) {
        qemu_epc_debug("failed to write payload\n");
    }
}

static const MemoryRegionOps qemu_epc_mmio_ob_window_ops = {
    .read = qemu_epc_mmio_ob_window_read,
    .write = qemu_epc_mmio_ob_window_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void qemu_epc_realize(PCIDevice *pci_dev, Error **errp)
{
    QemuEPCState *s = QEMU_EPC(pci_dev);

    memory_region_init_io(&s->ctrl_mr, OBJECT(s), &qemu_epc_mmio_ctrl_ops, s,
                          "qemu-epc/ctrl", pow2ceil(QEMU_EPC_CTRL_SIZE));
    memory_region_init_io(&s->pci_cfg_mr, OBJECT(s), &qemu_epc_mmio_pci_cfg_ops,
                          s, "qemu-epc/pci-cfg", PCIE_CONFIG_SPACE_SIZE);
    memory_region_init_io(&s->bar_cfg_mr, OBJECT(s), &qemu_epc_mmio_bar_cfg_ops,
                          s, "qemu-epc/bar-cfg",
                          pow2ceil(QEMU_EPC_BAR_CFG_SIZE));
    memory_region_init_io(&s->ob_window_mr, OBJECT(s),
                          &qemu_epc_mmio_ob_window_ops, s, "qemu-epc/ob_window",
                          QEMU_EPC_OB_WINDOW_SIZE);

    pci_register_bar(pci_dev, QEMU_EPC_BAR_CTRL, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->ctrl_mr);
    pci_register_bar(pci_dev, QEMU_EPC_BAR_PCI_CFG,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->pci_cfg_mr);
    pci_register_bar(pci_dev, QEMU_EPC_BAR_BAR_CFG,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar_cfg_mr);
    pci_register_bar(pci_dev, QEMU_EPC_BAR_OB_WINDOW,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->ob_window_mr);
}

static void qemu_epc_exit(PCIDevice *dev) {}

static void qemu_epc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = qemu_epc_realize;
    k->exit = qemu_epc_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = PCI_DEVICE_ID_REDHAT_QEMU_EPC;
    k->revision = QEMU_EPC_REVISON;
    k->class_id = PCI_CLASS_OTHERS;

    dc->desc = "QEMU Endpoint Controller device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo qemu_epc_info = {
    .name = TYPE_QEMU_EPC,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(QemuEPCState),
    .class_init = qemu_epc_class_init,
    .interfaces = (InterfaceInfo[]){
        {INTERFACE_CONVENTIONAL_PCI_DEVICE},
        {}
    },
};

static void qemu_epc_register_type(void)
{
    type_register_static(&qemu_epc_info);
}

type_init(qemu_epc_register_type);

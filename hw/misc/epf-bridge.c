/*
 * QEMU PCIe Endpoint device
 */

#include "qemu/osdep.h"
#include "qom/object.h"
#include "qapi/error.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/msi.h"

#include "qemu-epc-comm.h"

#define DEBUG_EPF_BRIDGE
#ifdef DEBUG_EPF_BRIDGE
#include "qemu/log.h"
#define epf_brd_debug(...) qemu_log("EPFBridge: " __VA_ARGS__)
#else
#define epf_brd_debug(...) do {} while (0)
#endif

struct EPFBridgeState {
    /*< private >*/
    PCIDevice dev;

    /*< public >*/
    QemuThread srv_thread;
    int req_fd;
    int srv_fd;

    struct bar_meta_data {
        MemoryRegion region;
        struct EPFBridgeState *s;
        uint8_t bar_no;
    } bar[6];
};

#define TYPE_EPF_BRIDGE "epf-bridge"
OBJECT_DECLARE_SIMPLE_TYPE(EPFBridgeState, EPF_BRIDGE);

static int epf_bridge_connect_epc(const char *uds_path)
{
    struct sockaddr_un sun = {};
    int err;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        epf_brd_debug("failed to create socket\n");
        return -1;
    }

    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, uds_path);

    err = connect(fd, (const struct sockaddr *)&sun, sizeof(sun));
    if (err == -1) {
        epf_brd_debug("failed to connect server\n");
        return -1;
    }

    return fd;
}

static int epf_bridge_handle_tlp_mr(EPFBridgeState *s, struct pci_tlp_mem *tlp)
{
    size_t addr = qemu_epc_comm_get_pci_addr_from_tlp(tlp);
    size_t length = qemu_epc_comm_tlp_data_length(&tlp->dw0);
    void *buf;
    int err;

    buf = pci_dma_map(&s->dev, addr, &length, DMA_DIRECTION_TO_DEVICE);
    if (!buf) {
        return -1;
    }

    err = qemu_epc_comm_comp_with_data(s->srv_fd, buf, length);

    pci_dma_unmap(&s->dev, buf, length, DMA_DIRECTION_TO_DEVICE, length);

    return err;
}

static int epf_bridge_handle_tlp_mw(EPFBridgeState *s, struct pci_tlp_mem *tlp)
{
    size_t addr = qemu_epc_comm_get_pci_addr_from_tlp(tlp);
    size_t length = qemu_epc_comm_tlp_data_length(&tlp->dw0);
    void *buf;
    int err;

    buf = pci_dma_map(&s->dev, addr, &length, DMA_DIRECTION_FROM_DEVICE);
    if (!buf) {
        return -1;
    }

    err = qemu_epc_comm_load_data(s->srv_fd, buf, length);

    pci_dma_unmap(&s->dev, buf, length, DMA_DIRECTION_FROM_DEVICE, length);

    return err;
}

static int epf_bridge_handle_tlp_msg(EPFBridgeState *s, struct pci_tlp_msg *tlp)
{
    enum PCI_TLP_IRQ_NUM irqn;

    irqn = qemu_epc_comm_irqn_from_tlp(tlp);
    if (irqn == PCI_TLP_IRQ_INVALID) {
        return -1;
    }

    pci_set_irq(&s->dev, 1);
    pci_set_irq(&s->dev, 0);

    return 0;
}

static int qemu_epc_handle_tlp(EPFBridgeState *s, struct qemu_epc_msg_hdr *mhdr)
{
    int err;
    uint32_t tlp_hdr[4] = {};
    struct pci_tlp_hdr_dw0 *dw0;

    err = qemu_epc_comm_recv_tlp(s->srv_fd, tlp_hdr);
    if (err) {
        epf_brd_debug("failed to receive tlp packet header\n");
        return err;
    }

    dw0 = (struct pci_tlp_hdr_dw0 *)&tlp_hdr[0];

    switch (dw0->fmt_type) {
    case PCI_TLP_TYPE_MR:
        err = epf_bridge_handle_tlp_mr(s, (struct pci_tlp_mem *)tlp_hdr);
        if (err) {
            epf_brd_debug("Failed to handle memory read tlp\n");
            return err;
        }
        break;
    case PCI_TLP_TYPE_MW:
        err = epf_bridge_handle_tlp_mw(s, (struct pci_tlp_mem *)tlp_hdr);
        if (err) {
            epf_brd_debug("Failed to handle memory write tlp\n");
            return err;
        }
        break;
    case PCI_TLP_TYPE_MSG:
        err = epf_bridge_handle_tlp_msg(s, (struct pci_tlp_msg *)tlp_hdr);
        if (err) {
            epf_brd_debug("failed to handle message tlp\n");
            return err;
        }
        break;
    default:
        epf_brd_debug("Not yet supported the type %d\n", dw0->fmt_type);
        return -1;
    }

    return 0;
}

static void *epf_bridge_srv_thread(void *opaque)
{
    EPFBridgeState *s = opaque;
    int err;
    struct qemu_epc_msg_hdr hdr;

    while (1) {
        err = qemu_epc_comm_recv_msg(s->srv_fd, &hdr);
        if (err) {
            epf_brd_debug("failed to receive message\n");
            break;
        }

        switch (hdr.type) {
        case QEMU_EPC_MSG_TYPE_TLP:
            err = qemu_epc_handle_tlp(s, &hdr);
            if (err) {
                epf_brd_debug("failed to handle TLP\n");
                goto done;
            }
            break;
        default:
            epf_brd_debug("the command type %d is not implemented yet\n",
                          hdr.type);
            goto done;
        }
    }
done:
    return NULL;
}

static int epf_bridge_launch_srv_and_pass_fd(EPFBridgeState *s)
{
    int err;
    int fd[2];

    err = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if (err < 0) {
        epf_brd_debug("failed to create sockpair\n");
        return err;
    }

    s->srv_fd = fd[0];

    qemu_thread_create(&s->srv_thread, "epf-bridge", epf_bridge_srv_thread, s,
                       QEMU_THREAD_JOINABLE);

    return qemu_epc_comm_pass_fd(s->req_fd, fd[1]);
}

static int epf_bridge_setup_irqs(EPFBridgeState *s, PCIDevice *pci_dev)
{
    int err;
    uint32_t int_line_pin;

    err = qemu_epc_comm_config_read(s->req_fd, PCI_INTERRUPT_LINE,
                                    &int_line_pin);
    if (err) {
        return err;
    }

    pci_config_set_interrupt_pin(pci_dev->config, (int_line_pin >> 8) & 0xff);

    /* msi and msi-x is not supporeted yet. */

    return 0;
}

static uint64_t epf_bridge_mbar_mmio_read(void *opaque, hwaddr addr,
                                          unsigned size)
{
    struct bar_meta_data *bar = opaque;
    uint64_t data;
    EPFBridgeState *s = bar->s;
    int err;

    err = qemu_epc_comm_bar_read(s->req_fd, bar->bar_no, addr, &data, size);
    if (err) {
        return 0;
    }
    epf_brd_debug("%s: %d: addr 0x%lx size 0x%x, data 0x%lx\n", __func__,
                  bar->bar_no, addr, size, data);

    return data;
}

static void epf_bridge_mbar_mmio_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size)
{
    struct bar_meta_data *bar = opaque;
    EPFBridgeState *s = bar->s;
    int err;

    epf_brd_debug("%s: bar %d addr 0x%lx size 0x%x, data 0x%lx\n", __func__,
                  bar->bar_no, addr, size, data);
    err = qemu_epc_comm_bar_write(s->req_fd, bar->bar_no, addr, (void *)&data,
                                  size);
    if (err) {
        epf_brd_debug("Failed to write bar\n");
    }
}

static const MemoryRegionOps epf_bridge_mbar_mmio_ops = {
    .read = epf_bridge_mbar_mmio_read,
    .write = epf_bridge_mbar_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static const char *bar_name[] = {
    TYPE_EPF_BRIDGE"/bar0",
    TYPE_EPF_BRIDGE"/bar1",
    TYPE_EPF_BRIDGE"/bar2",
    TYPE_EPF_BRIDGE"/bar3",
    TYPE_EPF_BRIDGE"/bar4",
    TYPE_EPF_BRIDGE"/bar5",
};

static int epf_bridge_setup_bars(EPFBridgeState *s, PCIDevice *pci_dev)
{
    struct pci_bar bar;
    int err;

    for (int i = 0; i < 6; i++) {
        err = qemu_epc_comm_req_bar(s->req_fd, i, &bar);
        if (err) {
            return err;
        }

        struct bar_meta_data *meta = &s->bar[i];
        meta->s = s;
        meta->bar_no = i;

        if (bar.size == 0) {
            continue;
        }

        if (bar.flags & 0x1) {
            /* I/O type bar */

            /*
             * Not supported yet, because the linux PCI endpoint framework
             * doesn't support I/O BAR acessing.
             */
        } else {
            epf_brd_debug("setup bar %d: size 0x%lx\n", i, bar.size);
            /* Memory type bar */
            memory_region_init_io(&meta->region, OBJECT(s),
                                  &epf_bridge_mbar_mmio_ops, meta, bar_name[i],
                                  bar.size);
            pci_register_bar(pci_dev, i, PCI_BASE_ADDRESS_SPACE_MEMORY,
                             &meta->region);
        }
    }

    return 0;
}

static int epf_bridge_setup_pci_cfg_hdr(EPFBridgeState *s, PCIDevice *pci_dev)
{
    uint32_t data;
    int err;
    uint16_t vendor_id, device_id;
    uint8_t revision, class_id;

    err = qemu_epc_comm_config_read(s->req_fd, PCI_VENDOR_ID, &data);
    if (err) {
        epf_brd_debug("failed to load configuration space: vendor_id: %d\n",
                      err);
        return err;
    }

    vendor_id = data & 0xffff;
    device_id = data >> 16;

    err = qemu_epc_comm_config_read(s->req_fd, PCI_REVISION_ID, &data);
    if (err) {
        epf_brd_debug("failed to load configuration space: revision: %d\n",
                      err);
        return err;
    }

    revision = data & 0xff;
    class_id = data >> 8;

    pci_config_set_vendor_id(pci_dev->config, vendor_id);
    pci_config_set_device_id(pci_dev->config, device_id);
    pci_config_set_revision(pci_dev->config, revision);
    pci_config_set_class(pci_dev->config, class_id);

    return 0;
}

static void epf_bridge_realize(PCIDevice *pci_dev, Error ** errp)
{
    EPFBridgeState *s = EPF_BRIDGE(pci_dev);
    int err;

    s->req_fd = epf_bridge_connect_epc(QEMU_EPC_SOCK_PATH);
    if (s->req_fd < 0) {
        error_setg(errp, "failed to connect server");
        return;
    }

    err = qemu_epc_comm_check_protcol_ver(s->req_fd);
    if (err) {
        error_setg(errp, "The protocol version is not compatible");
        return;
    }

    err = epf_bridge_launch_srv_and_pass_fd(s);
    if (err) {
        error_setg(errp, "Failed to pass a fd to receive request");
        return;
    }

    err = epf_bridge_setup_pci_cfg_hdr(s, pci_dev);
    if (err) {
        error_setg(errp, "failed to setup pci configuration space");
        return;
    }

    err = epf_bridge_setup_bars(s, pci_dev);
    if (err) {
        error_setg(errp, "failed to setup BAR");
        return;
    }

    err = epf_bridge_setup_irqs(s, pci_dev);
    if (err) {
        error_setg(errp, "failed to setup irqs");
        return;
    }
}

static void epf_bridge_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = epf_bridge_realize;

    dc->desc = "PCI EP function bridge device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo epf_bridge_dev_info = {
    .name = TYPE_EPF_BRIDGE,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(EPFBridgeState),
    .class_init = epf_bridge_class_init,
    .interfaces = (InterfaceInfo[]){
        {INTERFACE_CONVENTIONAL_PCI_DEVICE},
        {}
    },
};

static void epf_bridge_register_type(void)
{
    type_register_static(&epf_bridge_dev_info);
}

type_init(epf_bridge_register_type);

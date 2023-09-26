#include "qemu/osdep.h"

#include "hw/pci/pci_device.h"
#include "hw/remote/machine.h"
#include "monitor/monitor.h"
#include "qapi/error.h"
#include "io/channel.h"
#include "io/channel-util.h"

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

    RemoteCommDev rcom;
    /* PCIDevice for remote device */
    PCIDevice rpdev;
    int fd;
};

#define TYPE_QEMU_EPC "qemu-epc"
OBJECT_DECLARE_SIMPLE_TYPE(QemuEPCState, QEMU_EPC);

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
    // QemuEPCState *s = opaque;

    qemu_epc_debug("CTRL read: addr 0x%lx, size 0x%x\n", addr, size);

    // switch (addr) {
    // case QEMU_EPC_CTRL_OFF_WIN_START:
    //     return s->ob_window_mr.addr;
    // case QEMU_EPC_CTRL_OFF_WIN_START + sizeof(uint32_t):
    //     return s->ob_window_mr.addr >> 32;
    // case QEMU_EPC_CTRL_OFF_WIN_SIZE:
    //     return 0x100000;
    // case QEMU_EPC_CTRL_OFF_WIN_SIZE + sizeof(uint32_t):
    //     return 0;
    // case QEMU_EPC_CTRL_OFF_OB_MAP_MASK:
    //     return s->ob_map_mask;
    // default:
    //     qemu_epc_debug("unexpected read found: %ld\n", addr);
    // }

    return 0;
}

static void qemu_epc_mmio_ctrl_write(void *opaque, hwaddr addr, uint64_t val,
                                     unsigned size)
{
    // QemuEPCState *s = opaque;
    // uint64_t *tmp;

    qemu_epc_debug("CTRL write: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_CTRL_OFF_START:
        // TODO
        return;
    case QEMU_EPC_CTRL_OFF_IRQ_TYPE:
        // s->irq_type = val;
        break;
    case QEMU_EPC_CTRL_OFF_IRQ_NUM:
        // qemu_epc_handle_ctl_irq(s, val);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_MASK:
        // s->ob_map_mask = val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_IDX:
        // s->ob_idx = val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PHYS:
        // tmp = &s->ob_map[s->ob_idx].phys;
        // *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PHYS + sizeof(uint32_t):
        // tmp = &s->ob_map[s->ob_idx].phys;
        // *tmp = (*tmp & 0xffffffff) | (val << 32);
        // qemu_epc_debug("ob map phys: %d: 0x%lx\n", s->ob_idx, *tmp);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PCI:
        // tmp = &s->ob_map[s->ob_idx].pci;
        // *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_PCI + sizeof(uint32_t):
        // tmp = &s->ob_map[s->ob_idx].pci;
        // *tmp = (*tmp & 0xffffffff) | (val << 32);
        // qemu_epc_debug("ob map pci: %d: 0x%lx\n", s->ob_idx, *tmp);
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_SIZE:
        // tmp = &s->ob_map[s->ob_idx].size;
        // *tmp = (*tmp & ~0xffffffff) | val;
        break;
    case QEMU_EPC_CTRL_OFF_OB_MAP_SIZE + sizeof(uint32_t):
        // tmp = &s->ob_map[s->ob_idx].size;
        // *tmp = (*tmp & 0xffffffff) | (val << 32);
        // qemu_epc_debug("ob map size: %d: 0x%lx\n", s->ob_idx, *tmp);
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

static uint64_t qemu_epc_mmio_pci_cfg_read(void *opaque, hwaddr addr,
                                           unsigned size)
{
    QemuEPCState *s = opaque;

    qemu_epc_debug("PCI cfg read: addr 0x%lx, size 0x%x\n", addr, size);

    if (addr + size > PCIE_CONFIG_SPACE_SIZE) {
        qemu_epc_debug("PCI cfg write: detect outbounds access: 0x%lx\n",
                       addr + size);
        return 0 ;
    }

    return pci_default_read_config(&s->rpdev, addr, size);
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

    pci_default_write_config(&s->rpdev, addr, val, size);

    return;
}

static const MemoryRegionOps qemu_epc_mmio_pci_cfg_ops = {
    .read = qemu_epc_mmio_pci_cfg_read,
    .write = qemu_epc_mmio_pci_cfg_write,
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

static uint64_t qemu_epc_mmio_bar_cfg_read(void *opaque, hwaddr addr,
                                           unsigned size)
{
    // QemuEPCState *s = opaque;

    qemu_epc_debug("BAR cfg read: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_BAR_CFG_OFF_MASK:
        // return s->bar_mask;
    case QEMU_EPC_BAR_CFG_OFF_NUMBER:
        // return s->bar_no;
    default:
        qemu_epc_debug("BAR cfg read: detects unexpected read: 0x%lx\n",
                       addr);
    }

    return 0;
}

static void qemu_epc_mmio_bar_cfg_write(void *opaque, hwaddr addr, uint64_t val,
                                        unsigned size)
{
    // QemuEPCState *s = opaque;
    // uint64_t tmp;

    qemu_epc_debug("BAR cfg write: addr 0x%lx, size 0x%x\n", addr, size);

    switch (addr) {
    case QEMU_EPC_BAR_CFG_OFF_MASK:
        // s->bar_mask = (uint8_t)val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_NUMBER:
        // s->bar_no = (uint8_t)val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_FLAGS:
        // if (s->bar_no > 5) {
        //     qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
        //     break;
        // }
        // s->bars[s->bar_no].flags = (uint8_t)val;
        // s->pcie_cfg_space[PCI_BASE_ADDRESS_0 + s->bar_no * sizeof(uint32_t)]
        //     = val;
        break;
    case QEMU_EPC_BAR_CFG_OFF_PHYS_ADDR:
        // if (s->bar_no > 5) {
        //     qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
        //     break;
        // }
        // if (size == sizeof(uint32_t)) {
        //     tmp = (s->bars[s->bar_no].phys_addr & ~0xffffffffUL) | val;
        // } else if (size == sizeof(uint64_t)) {
        //     tmp = val;
        // } else {
        //     qemu_epc_debug("BAR cfg write: write size is invalid\n");
        //     break;
        // }
        // s->bars[s->bar_no].phys_addr = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_PHYS_ADDR + sizeof(uint32_t):
        // if (s->bar_no > 5) {
        //     qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
        //     break;
        // }
        // if (size != sizeof(uint32_t)) {
        //     qemu_epc_debug("BAR cfg write: write size is invalid\n");
        //     break;
        // }
        // tmp = (s->bars[s->bar_no].phys_addr & 0xffffffffUL) | (val << 32);
        // s->bars[s->bar_no].phys_addr = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_SIZE:
        // if (s->bar_no > 5) {
        //     qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
        //     break;
        // }
        // if (size == sizeof(uint32_t)) {
        //     tmp = (s->bars[s->bar_no].size & ~0xffffffffUL) | val;
        // } else if (size == sizeof(uint64_t)) {
        //     tmp = val;
        // } else {
        //     qemu_epc_debug("BAR cfg write: write size is invalid\n");
        //     break;
        // }
        // s->bars[s->bar_no].size = tmp;
        break;
    case QEMU_EPC_BAR_CFG_OFF_SIZE + sizeof(uint32_t):
        // if (s->bar_no > 5) {
        //     qemu_epc_debug("Selected BAR(%d) is invalid\n", s->bar_no);
        //     break;
        // }
        //
        // if (size != sizeof(uint32_t)) {
        //     qemu_epc_debug("BAR cfg write: write size is invalid\n");
        //     break;
        // }
        // tmp = (s->bars[s->bar_no].size & 0xffffffffUL) | (val << 32);
        // s->bars[s->bar_no].size = tmp;
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

enum {
    QEMU_EPC_BAR_CTRL = 0,
    QEMU_EPC_BAR_PCI_CFG = 1,
    QEMU_EPC_BAR_BAR_CFG = 2,
    QEMU_EPC_BAR_OB_WINDOW = 3,
};

static void qemu_epc_realize(PCIDevice *pci_dev, Error **errp)
{
    QemuEPCState *s = QEMU_EPC(pci_dev);
    QIOChannel *ioc;
    Coroutine *co;

    {
        memory_region_init_io(&s->ctrl_mr, OBJECT(s), &qemu_epc_mmio_ctrl_ops, s,
                          "qemu-epc/ctrl", pow2ceil(QEMU_EPC_CTRL_SIZE));
        memory_region_init_io(&s->pci_cfg_mr, OBJECT(s), &qemu_epc_mmio_pci_cfg_ops,
                          s, "qemu-epc/pci-cfg", PCIE_CONFIG_SPACE_SIZE);
        memory_region_init_io(&s->bar_cfg_mr, OBJECT(s), &qemu_epc_mmio_bar_cfg_ops,
                          s, "qemu-epc/bar-cfg",
                          pow2ceil(QEMU_EPC_BAR_CFG_SIZE));

    }
    {
        pci_register_bar(pci_dev, QEMU_EPC_BAR_CTRL, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->ctrl_mr);
        pci_register_bar(pci_dev, QEMU_EPC_BAR_PCI_CFG,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->pci_cfg_mr);
        pci_register_bar(pci_dev, QEMU_EPC_BAR_BAR_CFG,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar_cfg_mr);

    }

    ioc = qio_channel_new_fd(s->fd, errp);
    if (!ioc){
        error_report_err(*errp);
        return;
    }

    qio_channel_set_blocking(ioc, false, NULL);

    pci_config_alloc(&s->rpdev);

    s->rcom = (RemoteCommDev) {
        .ioc = ioc,
        .dev = &s->rpdev,
        .is_system = false,
    };

    co = qemu_coroutine_create(mpqemu_remote_msg_loop_co, &s->rcom);
    qemu_coroutine_enter(co);
}

static void qemu_epc_remote_object_set_fd(Object *obj, const char* str, Error **errp)
{
    QemuEPCState *s = QEMU_EPC(obj);
    int fd;

    fd = monitor_fd_param(monitor_cur(), str, errp);
    if (fd == -1) {
        error_prepend(errp, "Could not parse remote object fd %s:", str);
        return;
    }

    if (!fd_is_socket(fd)) {
        error_setg(errp, "File descriptor '%s' is not a socket", str);
        close(fd);
        return;
    }

    s->fd = fd;
}

static void qemu_epc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = qemu_epc_realize;
    // k->exit = qemu_epc_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = PCI_DEVICE_ID_REDHAT_QEMU_EPC;
    k->revision = QEMU_EPC_REVISON;
    k->class_id = PCI_CLASS_OTHERS;

    dc->desc = "QEMU Endpoint Controller device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    object_class_property_add_str(klass, "fd", NULL, qemu_epc_remote_object_set_fd);
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

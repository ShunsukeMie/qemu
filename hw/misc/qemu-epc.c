/*
 * QEMU PCI Endpoint Controller device
 */

#include "qemu/osdep.h"
#include "qom/object.h"

#include "qemu/log.h"

#include "qapi/error.h"
#include "qapi/qapi-visit-sockets.h"

#include "hw/pci/pci_device.h"

#include "libvfio-user.h"

#define DEBUG_QEMU_EPC
#ifdef DEBUG_QEMU_EPC
#define qemu_epc_debug(fmt, ...) qemu_log("qemu_epc: " fmt "\n", ## __VA_ARGS__)
#else
#define qemu_epc_debug(...)                                                    \
  do {                                                                         \
  } while (0)
#endif

struct QEPCState {
  /*< private >*/
  PCIDevice dev;

  vfu_ctx_t *vfu;
  int vfu_fd;

  const char *sock_path;

  /*< public >*/
  MemoryRegion ctrl_mr, pci_cfg_mr, bar_cfg_mr;
  MemoryRegion ob_window_mr;

  QemuThread thread;
};

#define TYPE_QEMU_EPC "qemu-epc"
OBJECT_DECLARE_SIMPLE_TYPE(QEPCState, QEMU_EPC)

#define QEPC_REVISION 0x01

enum {
  QEPC_BAR_CTRL = 0,
  QEPC_BAR_PCI_CFG = 1,
  QEPC_BAR_BAR_CFG = 2,
  QEPC_BAR_OB_WINDOWS = 3,
};

#define QEPC_CTRL_OFF_START (0x00)
#define QEPC_CTRL_OFF_WIN_START (0x08)
#define QEPC_CTRL_OFF_WIN_SIZE (0x10)
#define QEPC_CTRL_OFF_IRQ_TYPE (0x18)
#define QEPC_CTRL_OFF_IRQ_NUM (0x1c)
#define QEPC_CTRL_OFF_OB_IDX (0x20)
#define QEPC_CTRL_OFF_OB_FLAG (0x24)
#define QEPC_CTRL_OFF_OB_PHYS (0x28)
#define QEPC_CTRL_OFF_OB_PCI (0x30)
#define QEPC_CTRL_OFF_OB_SIZE (0x38)
#define QEPC_CTRL_SIZE (QEPC_CTRL_OFF_OB_SIZE + sizeof(uint64_t))

static uint64_t qepc_ctrl_mmio_read(void *opaque, hwaddr addr, unsigned size) {
  QEPCState *s = opaque;

  qemu_epc_debug("CTRL read: addr 0x%lx, size 0x%x", addr, size);

  switch (addr) {
  case QEPC_CTRL_OFF_WIN_START:
    return s->ob_window_mr.addr;
  case QEPC_CTRL_OFF_WIN_START + sizeof(uint32_t):
    return s->ob_window_mr.addr >> 32;
  case QEPC_CTRL_OFF_WIN_SIZE:
    return 0x100000;
  case QEPC_CTRL_OFF_WIN_SIZE + sizeof(uint32_t):
    return 0;
  default:;
  }

  return 0;
}

static ssize_t qepc_pci_cfg_access(vfu_ctx_t *vfu_ctx, char *const buf,
                                   size_t count, loff_t offset,
                                   const bool is_write) {
  QEPCState *s = vfu_get_private(vfu_ctx);

    qemu_epc_debug("%s: %s: offset 0x%lx, size 0x%lx", __func__, is_write ? "write" : "read",
                   offset, count);
  return count;
}

/*
static void *qepc_thread(void *opaque) {
  int err;
  QEPCState *s = opaque;

  qemu_epc_debug("start thread vfu thread");

  s->vfu = vfu_create_ctx(VFU_TRANS_SOCK, s->sock_path,
                          LIBVFIO_USER_FLAG_ATTACH_NB, s, VFU_DEV_TYPE_PCI);
  if (!s->vfu) {
    return NULL;
  }

  err = vfu_pci_init(s->vfu, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0);
  if (err) {
    return NULL;
  }

  err = vfu_setup_region(s->vfu, VFU_PCI_DEV_CFG_REGION_IDX,
                         PCIE_CONFIG_SPACE_SIZE, &qepc_pci_cfg_access,
                         VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB, NULL,
                         0, -1, 0);
  if (err) {
    qemu_epc_debug("failed at vfu_setup_region");
    return NULL;
  }
  // setup bars
  // setup irqs
  // vfu_realize_ctx
  err = vfu_realize_ctx(s->vfu);
  if (err) {
    qemu_epc_debug("failed at vfu_realize_ctx");
    return NULL;
  }
  // vfu_get_poll_fd
  // qemu_set_fd_handler(pollfd, );


  return NULL;
}
*/

static void qepc_vfu_run(void *opaque)
{
    QEPCState *s = opaque;
    int err = -1;

    qemu_epc_debug("starting vfu main loop");

    while(err != 0) {
        err = vfu_run_ctx(s->vfu);
        if (err < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == ENOTCONN){
                break;
            } else {
                break;
            }
        }
    }
}

static void qepc_vfu_attach_ctx(void *opaque)
{
    QEPCState *s = opaque;
    int err;

    qemu_epc_debug("attach vfu client");
    qemu_set_fd_handler(s->vfu_fd, NULL, NULL, NULL);

retry:
    err = vfu_attach_ctx(s->vfu);
    if (err < 0) {
        if (err == EAGAIN || errno == EWOULDBLOCK) {
            goto retry;
        }
        return;
    }

    s->vfu_fd = vfu_get_poll_fd(s->vfu);
    if (s->vfu_fd < 0) {
        return;
    }

    qemu_set_fd_handler(s->vfu_fd, qepc_vfu_run, NULL, s);
}

static void qepc_vfu_log(vfu_ctx_t *vfu_ctx, int level, const char *msg){
    qemu_epc_debug("vfu: %d: %s", level, msg);
}

static int qepc_ctrl_handle_start(QEPCState *s, uint64_t val) {
  int err;

  s->vfu = vfu_create_ctx(VFU_TRANS_SOCK, s->sock_path,
                          LIBVFIO_USER_FLAG_ATTACH_NB, s, VFU_DEV_TYPE_PCI);
  if (!s->vfu) {
    qemu_epc_debug("failed at vfu_create_ctx");
    return -1;
  }

  vfu_setup_log(s->vfu, qepc_vfu_log, LOG_DEBUG);

  err = vfu_pci_init(s->vfu, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0);
  if (err) {
    qemu_epc_debug("failed at vfu_pci_init");
    return -1;
  }

  err = vfu_setup_region(s->vfu, VFU_PCI_DEV_CFG_REGION_IDX,
                         PCIE_CONFIG_SPACE_SIZE, &qepc_pci_cfg_access,
                         VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB, NULL,
                         0, -1, 0);
  if (err) {
    qemu_epc_debug("failed at vfu_setup_region");
    return -1;
  }
  // setup bars
  // setup irqs
  
  err = vfu_realize_ctx(s->vfu);
  if (err) {
    qemu_epc_debug("failed at vfu_realize_ctx");
    return -1;
  }

  s->vfu_fd = vfu_get_poll_fd(s->vfu);
  if (s->vfu_fd < 0) {
       qemu_epc_debug("failed at vfu_get_poll_fd");
        return -1;
  }

  qemu_epc_debug("listening vfu connection from %s", s->sock_path);
  qemu_set_fd_handler(s->vfu_fd, qepc_vfu_attach_ctx, NULL, s);

  return 0;
}

static void qepc_ctrl_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                                 unsigned size) {
  QEPCState *s = opaque;
  // uint64_t *tmp;

  qemu_epc_debug("CTRL write: addr 0x%lx, size 0x%x", addr, size);

  switch (addr) {
  case QEPC_CTRL_OFF_START:
    qepc_ctrl_handle_start(s, val);
    return;
  case QEPC_CTRL_OFF_IRQ_TYPE:
    // s->irq_type = val;
    break;
  case QEPC_CTRL_OFF_IRQ_NUM:
    // qemu_epc_handle_ctl_irq(s, val);
    break;
  case QEPC_CTRL_OFF_OB_IDX:
    // s->ob_idx = val;
    break;
  case QEPC_CTRL_OFF_OB_PHYS:
    // tmp = &s->ob_map[s->ob_idx].phys;
    // *tmp = (*tmp & ~0xffffffff) | val;
    break;
  case QEPC_CTRL_OFF_OB_PHYS + sizeof(uint32_t):
    // tmp = &s->ob_map[s->ob_idx].phys;
    // *tmp = (*tmp & 0xffffffff) | (val << 32);
    // qemu_epc_debug("ob map phys: %d: 0x%lx\n", s->ob_idx, *tmp);
    break;
  case QEPC_CTRL_OFF_OB_PCI:
    // tmp = &s->ob_map[s->ob_idx].pci;
    // *tmp = (*tmp & ~0xffffffff) | val;
    break;
  case QEPC_CTRL_OFF_OB_PCI + sizeof(uint32_t):
    // tmp = &s->ob_map[s->ob_idx].pci;
    // *tmp = (*tmp & 0xffffffff) | (val << 32);
    // qemu_epc_debug("ob map pci: %d: 0x%lx\n", s->ob_idx, *tmp);
    break;
  case QEPC_CTRL_OFF_OB_SIZE:
    // tmp = &s->ob_map[s->ob_idx].size;
    // *tmp = (*tmp & ~0xffffffff) | val;
    break;
  case QEPC_CTRL_OFF_OB_SIZE + sizeof(uint32_t):
    // tmp = &s->ob_map[s->ob_idx].size;
    // *tmp = (*tmp & 0xffffffff) | (val << 32);
    // qemu_epc_debug("ob map size: %d: 0x%lx\n", s->ob_idx, *tmp);
    break;
  default:
      // qemu_epc_debug("CTRL write: invalid address 0x%lx\n", addr);
      ;
  }
}

static const MemoryRegionOps qepc_ctrl_mmio_ops = {
    .read = qepc_ctrl_mmio_read,
    .write = qepc_ctrl_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

#define NUM_OB_WINDOW 5
#define OB_WINDOW_SIZE 0x40000000ULL

static void qepc_realize(PCIDevice *pci_dev, Error **errp) {
  QEPCState *s = QEMU_EPC(pci_dev);

  qemu_epc_debug("realize");

  // if (!s->socket) {
  //   error_setg(errp, "qemu-epc: socket should be set");
  //   return;
  // }

  memory_region_init_io(&s->ctrl_mr, OBJECT(s), &qepc_ctrl_mmio_ops, s,
                        "qemu-epc/ctrl", pow2ceil(QEPC_CTRL_SIZE));
  // memory_region_init(&s->ob_window_mr, NULL, "qemu-epc/ob",
  //                    pow2ceil(NUM_OB_WINDOW * OB_WINDOW_SIZE));

  // memory_region_init_io(&s->cfg_cfg_mr, OBJECT(s),
  // &qemu_epc_mmio_pci_cfg_ops,
  //                       s, "qemu-epc/cfg-cfg", PCIE_CONFIG_SPACE_SIZE);
  // memory_region_init_io(&s->bar_cfg_mr, OBJECT(s),
  // &qemu_epc_mmio_bar_cfg_ops,
  //                       s, "qemu-epc/bar-cfg",
  //                       pow2ceil(QEMU_EPC_BAR_CFG_SIZE));
  // memory_region_init_io(&s->ob_window_mr, OBJECT(s),
  //                       &qemu_epc_mmio_ob_window_ops, s,
  //                       "qemu-epc/ob_window", QEMU_EPC_OB_WINDOW_SIZE);

  pci_register_bar(pci_dev, QEPC_BAR_CTRL, PCI_BASE_ADDRESS_MEM_TYPE_32,
                   &s->ctrl_mr);
  // pci_register_bar(pci_dev, QEMU_EPC_BAR_PCI_CFG,
  //                  PCI_BASE_ADDRESS_SPACE_MEMORY, &s->pci_cfg_mr);
  // pci_register_bar(pci_dev, QEMU_EPC_BAR_BAR_CFG,
  //                  PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar_cfg_mr);
  // pci_register_bar(pci_dev, QEPC_BAR_OB_WINDOWS, PCI_BASE_ADDRESS_MEM_TYPE_64,
  //                  &s->ob_window_mr);
}

static void qepc_object_set_path (Object *obj, const char *str,
                                   Error **errp)
{
  QEPCState *s = QEMU_EPC(obj);

  qemu_epc_debug("socket path: %s", str);
  s->sock_path = g_strdup(str);
}

/*
static void qepc_object_set_socket(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp) {
  QEPCState *s = QEMU_EPC(obj);

  visit_type_SocketAddress(v, name, &s->socket, errp);
  if (s->socket->type != SOCKET_ADDRESS_TYPE_UNIX) {
    error_setg(errp, "qemu-epc: Unsupported socket type - %s",
               SocketAddressType_str(s->socket->type));

    s->socket = NULL;
    return;
  }
}
*/

static void qepc_class_init(ObjectClass *klass, void *data) {
  DeviceClass *dc = DEVICE_CLASS(klass);
  PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
  // QEPCState *state = QEMU_EPC_CLASS(klass);

  qemu_epc_debug("initialize class");

  object_class_property_add_str(klass, "path", NULL,
                            qepc_object_set_path);

  k->realize = qepc_realize;
  // k->exit = qepc_exit;
  k->vendor_id = PCI_VENDOR_ID_REDHAT;
  k->device_id = PCI_DEVICE_ID_REDHAT_QEMU_EPC;
  k->revision = QEPC_REVISION;
  k->class_id = PCI_CLASS_OTHERS;

  dc->desc = "QEMU Endpoint Controller device";
  set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo qepc_info = {
    .name = TYPE_QEMU_EPC,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(QEPCState),
    .class_init = qepc_class_init,
    .interfaces = (InterfaceInfo[]){{INTERFACE_CONVENTIONAL_PCI_DEVICE}, {}},
};

static void qemu_epc_register_type(void) { type_register_static(&qepc_info); }

type_init(qemu_epc_register_type);

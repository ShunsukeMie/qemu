#ifndef VFIO_USER_OBJ_H
#define VFIO_USER_OBJ_H

void vfu_object_set_bus_irq(PCIBus *pci_bus);
void vfu_setup_msi_cbs(PCIDevice *pci_dev);

#endif

/**
 * configfs to configure the PCI endpoint
 *
 * Copyright (C) 2017 Texas Instruments
 * Author: Kishon Vijay Abraham I <kishon@ti.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 of
 * the License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/pci-epc.h>
#include <linux/pci-epf.h>

struct pci_epf_info {
	struct config_group group;
	struct list_head list;
	struct pci_epf *epf;
};

struct pci_ep_info {
	struct config_group group;
	struct config_group pci_epf_group;
	/* mutex to protect pci_epf list */
	struct mutex lock;
	struct list_head pci_epf;
	const char *epc_name;
	struct pci_epc *epc;
};

static inline struct pci_epf_info *to_pci_epf_info(struct config_item *item)
{
	return container_of(to_config_group(item), struct pci_epf_info, group);
}

static inline struct pci_ep_info *to_pci_ep_info(struct config_item *item)
{
	return container_of(to_config_group(item), struct pci_ep_info, group);
}

#define PCI_EPF_HEADER_R(_name)						       \
static ssize_t pci_epf_##_name##_show(struct config_item *item,	char *page)    \
{									       \
	struct pci_epf *epf = to_pci_epf_info(item)->epf;		       \
	if (!epf->header) {						       \
		WARN_ON_ONCE("epf device not bound to function driver\n");     \
		return 0;						       \
	}								       \
	return sprintf(page, "0x%04x\n", epf->header->_name);		       \
}

#define PCI_EPF_HEADER_W_u32(_name)					       \
static ssize_t pci_epf_##_name##_store(struct config_item *item,	       \
				       const char *page, size_t len)	       \
{									       \
	u32 val;							       \
	int ret;							       \
	struct pci_epf *epf = to_pci_epf_info(item)->epf;		       \
	if (!epf->header) {						       \
		WARN_ON_ONCE("epf device not bound to function driver\n");     \
		return 0;						       \
	}								       \
	ret = kstrtou32(page, 0, &val);					       \
	if (ret)							       \
		return ret;						       \
	epf->header->_name = val;					       \
	return len;							       \
}

#define PCI_EPF_HEADER_W_u16(_name)					       \
static ssize_t pci_epf_##_name##_store(struct config_item *item,	       \
				       const char *page, size_t len)	       \
{									       \
	u16 val;							       \
	int ret;							       \
	struct pci_epf *epf = to_pci_epf_info(item)->epf;		       \
	if (!epf->header) {						       \
		WARN_ON_ONCE("epf device not bound to function driver\n");     \
		return 0;						       \
	}								       \
	ret = kstrtou16(page, 0, &val);					       \
	if (ret)							       \
		return ret;						       \
	epf->header->_name = val;					       \
	return len;							       \
}

#define PCI_EPF_HEADER_W_u8(_name)					       \
static ssize_t pci_epf_##_name##_store(struct config_item *item,	       \
				       const char *page, size_t len)	       \
{									       \
	u8 val;								       \
	int ret;							       \
	struct pci_epf *epf = to_pci_epf_info(item)->epf;		       \
	if (!epf->header) {						       \
		WARN_ON_ONCE("epf device not bound to function driver\n");     \
		return 0;						       \
	}								       \
	ret = kstrtou8(page, 0, &val);					       \
	if (ret)							       \
		return ret;						       \
	epf->header->_name = val;					       \
	return len;							       \
}

static ssize_t pci_epf_msi_interrupts_store(struct config_item *item,
					    const char *page, size_t len)
{
	u8 val;
	int ret;

	ret = kstrtou8(page, 0, &val);
	if (ret)
		return ret;

	to_pci_epf_info(item)->epf->msi_interrupts = val;

	return len;
}

static ssize_t pci_epf_msi_interrupts_show(struct config_item *item,
					   char *page)
{
	return sprintf(page, "%d\n",
		       to_pci_epf_info(item)->epf->msi_interrupts);
}

static ssize_t pci_epf_function_show(struct config_item *item,
				     char *page)
{
	return sprintf(page, "%s\n",
		       to_pci_epf_info(item)->epf->name);
}

PCI_EPF_HEADER_R(vendorid)
PCI_EPF_HEADER_W_u16(vendorid)

PCI_EPF_HEADER_R(deviceid)
PCI_EPF_HEADER_W_u16(deviceid)

PCI_EPF_HEADER_R(revid)
PCI_EPF_HEADER_W_u8(revid)

PCI_EPF_HEADER_R(progif_code)
PCI_EPF_HEADER_W_u8(progif_code)

PCI_EPF_HEADER_R(subclass_code)
PCI_EPF_HEADER_W_u8(subclass_code)

PCI_EPF_HEADER_R(baseclass_code)
PCI_EPF_HEADER_W_u8(baseclass_code)

PCI_EPF_HEADER_R(cache_line_size)
PCI_EPF_HEADER_W_u8(cache_line_size)

PCI_EPF_HEADER_R(subsys_vendor_id)
PCI_EPF_HEADER_W_u16(subsys_vendor_id)

PCI_EPF_HEADER_R(subsys_id)
PCI_EPF_HEADER_W_u16(subsys_id)

PCI_EPF_HEADER_R(interrupt_pin)
PCI_EPF_HEADER_W_u8(interrupt_pin)

CONFIGFS_ATTR(pci_epf_, vendorid);
CONFIGFS_ATTR(pci_epf_, deviceid);
CONFIGFS_ATTR(pci_epf_, revid);
CONFIGFS_ATTR(pci_epf_, progif_code);
CONFIGFS_ATTR(pci_epf_, subclass_code);
CONFIGFS_ATTR(pci_epf_, baseclass_code);
CONFIGFS_ATTR(pci_epf_, cache_line_size);
CONFIGFS_ATTR(pci_epf_, subsys_vendor_id);
CONFIGFS_ATTR(pci_epf_, subsys_id);
CONFIGFS_ATTR(pci_epf_, interrupt_pin);
CONFIGFS_ATTR(pci_epf_, msi_interrupts);
CONFIGFS_ATTR_RO(pci_epf_, function);

static struct configfs_attribute *pci_epf_attrs[] = {
	&pci_epf_attr_vendorid,
	&pci_epf_attr_deviceid,
	&pci_epf_attr_revid,
	&pci_epf_attr_progif_code,
	&pci_epf_attr_subclass_code,
	&pci_epf_attr_baseclass_code,
	&pci_epf_attr_cache_line_size,
	&pci_epf_attr_subsys_vendor_id,
	&pci_epf_attr_subsys_id,
	&pci_epf_attr_interrupt_pin,
	&pci_epf_attr_msi_interrupts,
	&pci_epf_attr_function,
	NULL,
};

static void pci_epf_release(struct config_item *item)
{
	struct pci_epf_info *epf_info = to_pci_epf_info(item);

	pci_epf_destroy(epf_info->epf);
	kfree(epf_info);
}

static struct configfs_item_operations pci_epf_ops = {
	.release		= pci_epf_release,
};

static struct config_item_type pci_epf_type = {
	.ct_item_ops	= &pci_epf_ops,
	.ct_attrs	= pci_epf_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *pci_epf_make(struct config_group *group,
					 const char *name)
{
	struct pci_epf_info *epf_info;
	struct pci_ep_info *ep_info;
	struct pci_epf *epf;

	epf_info = kzalloc(sizeof(*epf_info), GFP_KERNEL);
	if (!epf_info)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&epf_info->group, name, &pci_epf_type);

	epf = pci_epf_create(name);
	if (IS_ERR(epf)) {
		pr_err("failed to create endpoint function device\n");
		return ERR_PTR(-EINVAL);
	}

	epf_info->epf = epf;
	ep_info = container_of(group, struct pci_ep_info, pci_epf_group);

	mutex_lock(&ep_info->lock);
	list_add_tail(&epf_info->list, &ep_info->pci_epf);
	mutex_unlock(&ep_info->lock);

	return &epf_info->group;
}

static void pci_epf_drop(struct config_group *group, struct config_item *item)
{
	struct pci_ep_info *ep_info;
	struct pci_epf_info *epf_info = to_pci_epf_info(item);

	ep_info = container_of(group, struct pci_ep_info, pci_epf_group);

	pci_epf_unbind(epf_info->epf);
	pci_epc_remove_epf(ep_info->epc, epf_info->epf);

	mutex_lock(&ep_info->lock);
	list_del(&epf_info->list);
	mutex_unlock(&ep_info->lock);

	config_item_put(item);
}

static struct configfs_group_operations pci_epfs_ops = {
	.make_group	= &pci_epf_make,
	.drop_item	= &pci_epf_drop,
};

static struct config_item_type pci_epfs_type = {
	.ct_group_ops	= &pci_epfs_ops,
	.ct_owner	= THIS_MODULE,
};

static ssize_t pci_ep_epc_store(struct config_item *item, const char *page,
				size_t len)
{
	int ret;
	u8 func_no = 0;
	char *epc_name;
	struct pci_epc *epc;
	struct pci_epf *epf;
	struct pci_epf_info *epf_info;
	struct pci_ep_info *ep_info = to_pci_ep_info(item);

	epc_name = kstrdup(page, GFP_KERNEL);
	if (!epc_name)
		return -ENOMEM;
	if (epc_name[len - 1] == '\n')
		epc_name[len - 1] = '\0';

	if (ep_info->epc) {
		ret = -EBUSY;
		goto err;
	}

	epc = pci_epc_get(epc_name);
	if (IS_ERR(epc)) {
		ret = PTR_ERR(epc);
		goto err;
	}

	ep_info->epc = epc;
	ep_info->epc_name = epc_name;

	list_for_each_entry(epf_info, &ep_info->pci_epf, list) {
		epf = epf_info->epf;
		epf->func_no = func_no;
		epf->epc = epc;
		pci_epc_add_epf(epc, epf);
		pci_epf_bind(epf);
		func_no++;
	}

	return len;

err:
	kfree(epc_name);
	return ret;
}

static ssize_t pci_ep_epc_show(struct config_item *item, char *page)
{
	return sprintf(page, "%s\n",
		       to_pci_ep_info(item)->epc_name);
}

CONFIGFS_ATTR(pci_ep_, epc);

static struct configfs_attribute *pci_ep_attrs[] = {
	&pci_ep_attr_epc,
	NULL,
};

static void pci_ep_attr_release(struct config_item *item)
{
	struct pci_ep_info *ep_info = to_pci_ep_info(item);

	pci_epc_put(ep_info->epc);
	kfree(ep_info->epc_name);
	kfree(ep_info);
}

static struct configfs_item_operations pci_ep_device_ops = {
	.release	= pci_ep_attr_release,
};

static struct config_item_type pci_ep_device_type = {
	.ct_item_ops	= &pci_ep_device_ops,
	.ct_attrs	= pci_ep_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *pci_ep_make(struct config_group *group,
					const char *name)
{
	struct pci_ep_info *ep_info;

	ep_info = kzalloc(sizeof(*ep_info), GFP_KERNEL);
	if (!ep_info)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&ep_info->group, name, &pci_ep_device_type);
	config_group_init_type_name(&ep_info->pci_epf_group,
				    "epf", &pci_epfs_type);
	configfs_add_default_group(&ep_info->pci_epf_group, &ep_info->group);

	mutex_init(&ep_info->lock);
	INIT_LIST_HEAD(&ep_info->pci_epf);

	return &ep_info->group;
}

static void pci_ep_drop(struct config_group *group, struct config_item *item)
{
	config_item_put(item);
}

static struct configfs_group_operations pci_ep_ops = {
	.make_group	= &pci_ep_make,
	.drop_item	= &pci_ep_drop,
};

static struct config_item_type pci_ep_type = {
	.ct_group_ops	= &pci_ep_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem pci_ep_cfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "pci_ep",
			.ci_type = &pci_ep_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(pci_ep_cfs_subsys.su_mutex),
};

static int __init pci_ep_cfs_init(void)
{
	int ret;

	config_group_init(&pci_ep_cfs_subsys.su_group);

	ret = configfs_register_subsystem(&pci_ep_cfs_subsys);
	if (ret)
		pr_err("Error %d while registering subsystem %s\n",
		       ret, pci_ep_cfs_subsys.su_group.cg_item.ci_namebuf);

	return ret;
}
module_init(pci_ep_cfs_init);

static void __exit pci_ep_cfs_exit(void)
{
	configfs_unregister_subsystem(&pci_ep_cfs_subsys);
}
module_exit(pci_ep_cfs_exit);

MODULE_DESCRIPTION("PCI EP CONFIGFS");
MODULE_AUTHOR("Kishon Vijay Abraham I <kishon@ti.com>");
MODULE_LICENSE("GPL v2");

#
# Makefile for HSR
#

obj-$(CONFIG_HSR_PRP)	+= hsr-prp.o

hsr-prp-y		:= hsr_prp_main.o hsr_main.o prp_main.o \
			   hsr_prp_framereg.o hsr_prp_device.o hsr_netlink.o \
			   prp_netlink.o hsr_prp_slave.o hsr_prp_forward.o
hsr-prp-$(CONFIG_DEBUG_FS) += hsr_prp_debugfs.o

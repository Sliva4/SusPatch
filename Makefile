ifeq ($(CONFIG_SLIVA_PATCH),y)
$(info -- SUS patch was enabled!)
endif
ifeq ($(CONFIG_SLIVA_PATCH),n)
$(info -- SUS patch was disabled!)
endif
obj-$(CONFIG_SLIVA_PATCH) += sus.o

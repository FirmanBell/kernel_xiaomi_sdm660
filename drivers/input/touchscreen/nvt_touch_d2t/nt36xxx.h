// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 - 2018 Novatek, Inc.
 *
 * $Revision: 47247 $
 * $Date: 2019-07-10 10:41:36 +0800 (Wed, 10 Jul 2019) $
 *
 */

#ifndef		_LINUX_NVT_TOUCH_H
#define		_LINUX_NVT_TOUCH_H

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/uaccess.h>
#include "nt36xxx_mem_map.h"
#include <linux/regulator/consumer.h>
#include <uapi/linux/sched/types.h>

#define NVT_TOUCH_RST_PIN 980
#define NVT_TOUCH_INT_PIN 943

#define PINCTRL_STATE_ACTIVE		"pmx_ts_active"
#define PINCTRL_STATE_SUSPEND		"pmx_ts_suspend"
#define PINCTRL_STATE_RELEASE		"pmx_ts_release"
#define NVT_COORDS_ARR_SIZE 2

#define INT_TRIGGER_TYPE IRQ_TYPE_EDGE_RISING

#define NVT_I2C_NAME "NVT-ts"
#define I2C_BLDR_Address 0x01
#define I2C_FW_Address 0x01
#define I2C_HW_Address 0x62
#define NVT_TS_NAME "NVTCapacitiveTouchScreen"

#define TOUCH_DEFAULT_MAX_WIDTH 1080
#define TOUCH_DEFAULT_MAX_HEIGHT 2246
#define TOUCH_MAX_FINGER_NUM 10
#define TOUCH_FORCE_NUM 1000

#define NVT_TOUCH_SUPPORT_HW_RST 0

#define WAKEUP_GESTURE 1
#if WAKEUP_GESTURE
extern const uint16_t gesture_key_array[];
#endif
#define BOOT_UPDATE_FIRMWARE 0
#define BOOT_UPDATE_FIRMWARE_NAME "novatek_nt36672_d2t.fw"

#define TOUCH_STATE_WORKING 0x00
#define POINT_DATA_LEN 65

#define NVT_LOCKDOWN_SIZE	8
#define NVT_TOUCH_COUNT_DUMP
#ifdef NVT_TOUCH_COUNT_DUMP
#define TOUCH_COUNT_FILE_MAXSIZE 50
struct nvt_config_info {
	u8 tp_vendor;
	u8 tp_color;
	u8 tp_hw_version;
	const char *nvt_cfg_name;
	const char *nvt_limit_name;
#ifdef NVT_TOUCH_COUNT_DUMP
	const char *clicknum_file_name;
#endif
};
#endif

struct nvt_ts_data {
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct delayed_work nvt_fwu_work;
	uint16_t addr;
	int8_t phys[32];
	struct workqueue_struct *coord_workqueue;
	struct work_struct irq_work;
	struct notifier_block fb_notif;
	uint8_t fw_ver;
	uint8_t x_num;
	uint8_t y_num;
	uint16_t abs_x_max;
	uint16_t abs_y_max;
	uint8_t max_touch_num;
	uint32_t int_trigger_type;
	int32_t irq_gpio;
	uint32_t irq_flags;
	int32_t reset_gpio;
	uint32_t reset_flags;
	struct mutex lock;
	struct mutex pm_mutex;
	const struct nvt_ts_mem_map *mmap;
	uint8_t carrier_system;
	uint16_t nvt_pid;
	uint8_t xbuf[1025];
	struct mutex xbuf_lock;
	bool irq_enabled;
	struct nvt_config_info *config_array;
	struct pinctrl *ts_pinctrl;
	struct pinctrl_state *pinctrl_state_active;
	struct pinctrl_state *pinctrl_state_suspend;
	struct regulator *vddio_reg;
	struct regulator *lab_reg;
	struct regulator *ibb_reg;
	const char *vddio_reg_name;
	const char *lab_reg_name;
	const char *ibb_reg_name;
	const char *fw_name;
	u8 lockdown_info[NVT_LOCKDOWN_SIZE];
	size_t config_array_size;
#if WAKEUP_GESTURE
	int gesture_enabled;
#endif
	int current_index;
	bool tddi_tp_hw_reset;
	bool gesture_enabled_when_resume;
	bool gesture_disabled_when_resume;
	int32_t reset_tddi;
	int dbclick_count;
#ifdef NVT_TOUCH_COUNT_DUMP
	struct class *nvt_tp_class;
	struct device *nvt_touch_dev;
	bool dump_click_count;
	char *current_clicknum_file;
#endif
	bool dev_pm_suspend;
	struct completion dev_pm_suspend_completion;
};

#if WAKEUP_GESTURE
struct mi_mode_switch {
	struct nvt_ts_data *nvt_data;
	unsigned char mode;
	struct work_struct switch_mode_work;
};
#endif

typedef enum {
	RESET_STATE_INIT = 0xA0,// IC reset
	RESET_STATE_REK,		// ReK baseline
	RESET_STATE_REK_FINISH,	// baseline is ready
	RESET_STATE_NORMAL_RUN,	// normal run
	RESET_STATE_MAX  = 0xAF
} RST_COMPLETE_STATE;

typedef enum {
    EVENT_MAP_HOST_CMD                      = 0x50,
    EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE   = 0x51,
    EVENT_MAP_RESET_COMPLETE                = 0x60,
    EVENT_MAP_FWINFO                        = 0x78,
    EVENT_MAP_PROJECTID                     = 0x9A,
} I2C_EVENT_MAP;

extern struct nvt_ts_data *ts;
extern int32_t CTP_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern int32_t CTP_I2C_WRITE(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern void nvt_bootloader_reset(void);
extern void nvt_sw_reset_idle(void);
extern int32_t nvt_check_fw_reset_state(RST_COMPLETE_STATE check_reset_state);
extern int32_t nvt_get_fw_info(void);
extern int32_t nvt_clear_fw_status(void);
extern int32_t nvt_check_fw_status(void);
extern int32_t nvt_set_page(uint16_t i2c_addr, uint32_t addr);
extern void nvt_stop_crc_reboot(void);

#endif /* _LINUX_NVT_TOUCH_H */

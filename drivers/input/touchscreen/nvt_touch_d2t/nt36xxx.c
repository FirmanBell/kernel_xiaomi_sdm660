// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 - 2018 Novatek, Inc.
 *
 * $Revision: 47247 $
 * $Date: 2019-07-10 10:41:36 +0800 (Wed, 10 Jul 2019) $
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/input/mt.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/notifier.h>
#include <linux/fb.h>
#include "nt36xxx.h"

extern void mdss_panel_reset_skip_enable(bool enable);
extern bool mdss_panel_is_prim(void *fbinfo);

struct nvt_ts_data *ts;
static uint8_t bTouchIsAwake;
static int nvt_fb_notifier_callback(struct notifier_block *self,
				    unsigned long event, void *data);
#if BOOT_UPDATE_FIRMWARE
static struct workqueue_struct *nvt_fwu_wq;
extern void Boot_Update_Firmware(struct work_struct *work);
#endif

#if WAKEUP_GESTURE
#ifdef CONFIG_TOUCHSCREEN_COMMON
#include <linux/input/tp_common.h>
#endif
#define GESTURE_WORD_C 12
#define GESTURE_WORD_W 13
#define GESTURE_WORD_V 14
#define GESTURE_DOUBLE_CLICK 15
#define GESTURE_WORD_Z 16
#define GESTURE_WORD_M 17
#define GESTURE_WORD_O 18
#define GESTURE_WORD_e 19
#define GESTURE_WORD_S 20
#define GESTURE_SLIDE_UP 21
#define GESTURE_SLIDE_DOWN 22
#define GESTURE_SLIDE_LEFT 23
#define GESTURE_SLIDE_RIGHT 24
#define DATA_PROTOCOL 30
#define FUNCPAGE_GESTURE 1

const uint16_t gesture_key_array[] = {
	KEY_POWER, //GESTURE_WORD_C
	KEY_POWER, //GESTURE_WORD_W
	KEY_POWER, //GESTURE_WORD_V
	KEY_POWER, //GESTURE_DOUBLE_CLICK
	KEY_POWER, //GESTURE_WORD_Z
	KEY_POWER, //GESTURE_WORD_M
	KEY_POWER, //GESTURE_WORD_O
	KEY_POWER, //GESTURE_WORD_e
	KEY_POWER, //GESTURE_WORD_S
	KEY_POWER, //GESTURE_SLIDE_UP
	KEY_POWER, //GESTURE_SLIDE_DOWN
	KEY_POWER, //GESTURE_SLIDE_LEFT
	KEY_POWER, //GESTURE_SLIDE_RIGHT
};

#ifdef CONFIG_TOUCHSCREEN_COMMON
static ssize_t double_tap_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ts->gesture_enabled);
}

static ssize_t double_tap_store(struct kobject *kobj,
				       struct kobj_attribute *attr, const char *buf,
				       size_t count)
{
	int rc, val;

	rc = kstrtoint(buf, 10, &val);
	if (rc)
		return -EINVAL;

	ts->gesture_enabled = !!val;
	return count;
}

static struct tp_common_ops double_tap_ops = {
	.show = double_tap_show,
	.store = double_tap_store
};
#endif

void nvt_ts_wakeup_gesture_report(uint8_t gesture_id, uint8_t *data)
{
	uint32_t keycode = 0;
	uint8_t func_type = data[2];
	uint8_t func_id = data[3];

	if ((gesture_id == DATA_PROTOCOL) && (func_type == FUNCPAGE_GESTURE))
		gesture_id = func_id;
	else if (gesture_id > DATA_PROTOCOL)
		return;

	switch (gesture_id) {
	case GESTURE_WORD_C:
		keycode = gesture_key_array[0];
		break;
	case GESTURE_WORD_W:
		keycode = gesture_key_array[1];
		break;
	case GESTURE_WORD_V:
		keycode = gesture_key_array[2];
		break;
	case GESTURE_DOUBLE_CLICK:
		keycode = gesture_key_array[3];
		ts->dbclick_count++;
		break;
	case GESTURE_WORD_Z:
		keycode = gesture_key_array[4];
		break;
	case GESTURE_WORD_M:
		keycode = gesture_key_array[5];
		break;
	case GESTURE_WORD_O:
		keycode = gesture_key_array[6];
		break;
	case GESTURE_WORD_e:
		keycode = gesture_key_array[7];
		break;
	case GESTURE_WORD_S:
		keycode = gesture_key_array[8];
		break;
	case GESTURE_SLIDE_UP:
		keycode = gesture_key_array[9];
		break;
	case GESTURE_SLIDE_DOWN:
		keycode = gesture_key_array[10];
		break;
	case GESTURE_SLIDE_LEFT:
		keycode = gesture_key_array[11];
		break;
	case GESTURE_SLIDE_RIGHT:
		keycode = gesture_key_array[12];
		break;
	default:
		break;
	}

	if (keycode > 0) {
		input_report_key(ts->input_dev, keycode, 1);
		input_sync(ts->input_dev);
		input_report_key(ts->input_dev, keycode, 0);
		input_sync(ts->input_dev);
	}
}
#endif

static void __always_inline nvt_irq_enable(bool enable)
{
	struct irq_desc *desc;

	if (enable) {
		if (!ts->irq_enabled) {
			enable_irq(ts->client->irq);
			ts->irq_enabled = true;
		}
	} else {
		if (ts->irq_enabled) {
			disable_irq(ts->client->irq);
			ts->irq_enabled = false;
		}
	}

	desc = irq_to_desc(ts->client->irq);
}

int32_t CTP_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf,
			    uint16_t len)
{
	struct i2c_msg msgs[2];
	int32_t ret = -1;

	mutex_lock(&ts->xbuf_lock);

	msgs[0].flags = !I2C_M_RD;
	msgs[0].addr = address;
	msgs[0].len = 1;
	msgs[0].buf = &buf[0];

	msgs[1].flags = I2C_M_RD;
	msgs[1].addr = address;
	msgs[1].len = len - 1;
	msgs[1].buf = ts->xbuf;

	ret = i2c_transfer(client->adapter, msgs, 2);
	memcpy(buf + 1, ts->xbuf, len - 1);

	mutex_unlock(&ts->xbuf_lock);

	return ret;
}

int32_t CTP_I2C_WRITE(struct i2c_client *client, uint16_t address, uint8_t *buf,
			     uint16_t len)
{
	struct i2c_msg msg;
	int32_t ret = -1;

	mutex_lock(&ts->xbuf_lock);

	msg.flags = !I2C_M_RD;
	msg.addr = address;
	msg.len = len;
	memcpy(ts->xbuf, buf, len);
	msg.buf = ts->xbuf;

	ret = i2c_transfer(client->adapter, &msg, 1);

	mutex_unlock(&ts->xbuf_lock);

	return ret;
}

int32_t nvt_set_page(uint16_t i2c_addr, uint32_t addr)
{
	uint8_t buf[4] = { 0 };

	buf[0] = 0xFF;
	buf[1] = (addr >> 16) & 0xFF;
	buf[2] = (addr >> 8) & 0xFF;

	return CTP_I2C_WRITE(ts->client, i2c_addr, buf, 3);
}

void nvt_sw_reset_idle(void)
{
	uint8_t buf[4] = { 0 };

	buf[0] = 0x00;
	buf[1] = 0xA5;
	CTP_I2C_WRITE(ts->client, I2C_HW_Address, buf, 2);

	msleep(15);
}

void nvt_bootloader_reset(void)
{
	uint8_t buf[8] = { 0 };

	buf[0] = 0x00;
	buf[1] = 0x69;
	CTP_I2C_WRITE(ts->client, I2C_HW_Address, buf, 2);

	msleep(35);
}

int32_t nvt_clear_fw_status(void)
{
	uint8_t buf[8] = { 0 };

	nvt_set_page(I2C_FW_Address, ts->mmap->EVENT_BUF_ADDR |
		     EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

	buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
	buf[1] = 0x00;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 2);

	buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
	buf[1] = 0xFF;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 2);

	return 0;
}

int32_t nvt_check_fw_status(void)
{
	uint8_t buf[8] = { 0 };

	nvt_set_page(I2C_FW_Address, ts->mmap->EVENT_BUF_ADDR |
		     EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

	buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
	buf[1] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 2);

	return 0;
}

int32_t nvt_check_fw_reset_state(RST_COMPLETE_STATE check_reset_state)
{
	uint8_t buf[8] = { 0 };
	int32_t ret = 0;

	buf[0] = EVENT_MAP_RESET_COMPLETE;
	buf[1] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 6);

	return ret;
}

int32_t nvt_read_pid(void)
{
	uint8_t buf[3] = { 0 };
	int32_t ret = 0;

	nvt_set_page(I2C_FW_Address, ts->mmap->EVENT_BUF_ADDR |
		     EVENT_MAP_PROJECTID);

	buf[0] = EVENT_MAP_PROJECTID;
	buf[1] = 0x00;
	buf[2] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 3);

	ts->nvt_pid = (buf[2] << 8) + buf[1];

	return ret;
}

int32_t nvt_get_fw_info(void)
{
	uint8_t buf[64] = { 0 };
	uint32_t retry_count = 0;
	int32_t ret = 0;

info_retry:
	nvt_set_page(I2C_FW_Address, ts->mmap->EVENT_BUF_ADDR |
		     EVENT_MAP_FWINFO);

	buf[0] = EVENT_MAP_FWINFO;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 17);
	ts->x_num = buf[3];
	ts->y_num = buf[4];
	ts->abs_x_max = (uint16_t)((buf[5] << 8) | buf[6]);
	ts->abs_y_max = (uint16_t)((buf[7] << 8) | buf[8]);

	if ((buf[1] + buf[2]) != 0xFF) {
		ts->x_num = 18;
		ts->y_num = 32;
		ts->abs_x_max = TOUCH_DEFAULT_MAX_WIDTH;
		ts->abs_y_max = TOUCH_DEFAULT_MAX_HEIGHT;

		if (retry_count < 3) {
			retry_count++;
			goto info_retry;
		} else
			ret = -1;
	} else
		ret = 0;

	nvt_read_pid();

	return ret;
}

static int nvt_get_dt_coords(struct device *dev, char *name)
{
	int ret = 0;
	u32 coords[NVT_COORDS_ARR_SIZE] = { 0 };
	struct property *prop;
	struct device_node *np = dev->of_node;
	int coords_size;

	prop = of_find_property(np, name, NULL);
	if (!prop)
		return -EINVAL;
	if (!prop->value)
		return -ENODATA;

	coords_size = prop->length / sizeof(u32);
	if (coords_size != NVT_COORDS_ARR_SIZE) {
		return -EINVAL;
	}

	ret = of_property_read_u32_array(np, name, coords, coords_size);
	if (ret && (ret != -EINVAL)) {
		return -ENODATA;
	}

	if (!strcmp(name, "novatek,display-coords")) {
		ts->abs_x_max = coords[0];
		ts->abs_y_max = coords[1];
	} else {
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_OF
static int nvt_parse_dt(struct device *dev)
{
	struct device_node *mi, *np = dev->of_node;
	struct nvt_config_info *config_info;
	int retval;
	u32 temp_val;

	retval = nvt_get_dt_coords(dev, "novatek,display-coords");

	ts->reset_gpio = of_get_named_gpio_flags(np, "novatek,reset-gpio", 0, &ts->reset_flags);
	ts->tddi_tp_hw_reset = of_property_read_bool(np, "novatek,tddi-tp-hw-reset");
	ts->reset_tddi = of_get_named_gpio_flags(np, "novatek,reset-tddi", 0, NULL);
	ts->irq_gpio = of_get_named_gpio_flags(np, "novatek,irq-gpio", 0, &ts->irq_flags);

	retval = of_property_read_string(np, "novatek,vddio-reg-name", &ts->vddio_reg_name);
	if (retval < 0) {
		return retval;
	}

	retval = of_property_read_string(np, "novatek,lab-reg-name", &ts->lab_reg_name);
	if (retval < 0) {
		return retval;
	}

	retval = of_property_read_string(np, "novatek,ibb-reg-name", &ts->ibb_reg_name);
	if (retval < 0) {
		return retval;
	}

#ifdef NVT_TOUCH_COUNT_DUMP
	ts->dump_click_count =
		of_property_read_bool(np, "novatek,dump-click-count");
#endif
	retval = of_property_read_u32(np, "novatek,config-array-size",
				 (u32 *) &ts->config_array_size);
	if (retval) {
		return retval;
	}

	ts->config_array = devm_kzalloc(dev, ts->config_array_size *
					   sizeof(struct nvt_config_info),
					   GFP_KERNEL);

	if (!ts->config_array) {
		return -ENOMEM;
	}
	config_info = ts->config_array;
	for_each_child_of_node(np, mi) {
		retval = of_property_read_u32(mi,
				"novatek,tp-vendor", &temp_val);
		retval = of_property_read_u32(mi,
				"novatek,hw-version", &temp_val);
		retval = of_property_read_string(mi, "novatek,fw-name",
						 &config_info->nvt_cfg_name);
		retval = of_property_read_string(mi, "novatek,limit-name",
						 &config_info->nvt_limit_name);

#ifdef NVT_TOUCH_COUNT_DUMP
		if (ts->dump_click_count) {
			retval = of_property_read_string(mi, "novatek,clicknum-file-name",
							&config_info->clicknum_file_name);

			if (retval && (retval != -EINVAL)) {
				dev_err(dev,
					"Unable to read click count file name\n");
			} else
				dev_err(dev, "%s\n",
					config_info->clicknum_file_name);
		}

#endif
		config_info++;
	}

	return 0;
}
#else
static int nvt_parse_dt(struct device *dev)
{
#if NVT_TOUCH_SUPPORT_HW_RST
	ts->reset_gpio = NVT_TOUCH_RST_PIN;
#endif
	ts->irq_gpio = NVT_TOUCH_INT_PIN;

	return 0;
}
#endif

static const char *nvt_get_config(struct nvt_ts_data *ts)
{
	int i;

	for (i = 0; i < ts->config_array_size; i++) {
		if (ts->lockdown_info[0] ==
		     ts->config_array[i].tp_vendor)
			break;
	}

	if (i >= ts->config_array_size) {
		return BOOT_UPDATE_FIRMWARE_NAME;
	}

	ts->current_index = i;
#ifdef NVT_TOUCH_COUNT_DUMP
	if (ts->dump_click_count) {
		ts->current_clicknum_file =
			kzalloc(TOUCH_COUNT_FILE_MAXSIZE, GFP_KERNEL);
		strlcpy(ts->current_clicknum_file,
			ts->config_array[i].clicknum_file_name,
			TOUCH_COUNT_FILE_MAXSIZE);
	}

#endif
	return ts->config_array[i].nvt_cfg_name;
}

static int nvt_get_reg(struct nvt_ts_data *ts, bool get)
{
	int retval;

	if (!get) {
		retval = 0;
		goto regulator_put;
	}

	if ((ts->vddio_reg_name != NULL) && (*ts->vddio_reg_name != 0)) {
		ts->vddio_reg = regulator_get(&ts->client->dev,
				ts->vddio_reg_name);
		if (IS_ERR(ts->vddio_reg)) {
			retval = PTR_ERR(ts->vddio_reg);
			goto regulator_put;
		}
	}

	if ((ts->lab_reg_name != NULL) && (*ts->lab_reg_name != 0)) {
		ts->lab_reg = regulator_get(&ts->client->dev,
				ts->lab_reg_name);
		if (IS_ERR(ts->lab_reg)) {
			retval = PTR_ERR(ts->lab_reg);
			goto regulator_put;
		}
	}

	if ((ts->ibb_reg_name != NULL) && (*ts->ibb_reg_name != 0)) {
		ts->ibb_reg = regulator_get(&ts->client->dev,
				ts->ibb_reg_name);
		if (IS_ERR(ts->ibb_reg)) {
			retval = PTR_ERR(ts->ibb_reg);
			goto regulator_put;
		}
	}

	return 0;

regulator_put:
	if (ts->vddio_reg) {
		regulator_put(ts->vddio_reg);
		ts->vddio_reg = NULL;
	}
	if (ts->lab_reg) {
		regulator_put(ts->lab_reg);
		ts->lab_reg = NULL;
	}
	if (ts->ibb_reg) {
		regulator_put(ts->ibb_reg);
		ts->ibb_reg = NULL;
	}

	return retval;
}

static int nvt_enable_reg(struct nvt_ts_data *ts, bool enable)
{
	int retval;

	if (!enable) {
		retval = 0;
		goto disable_ibb_reg;
	}

	if (ts->vddio_reg) {
		retval = regulator_enable(ts->vddio_reg);
		if (retval < 0) {
			goto exit;
		}
	}

	if (ts->lab_reg && ts->lab_reg) {
		retval = regulator_enable(ts->lab_reg);
		if (retval < 0) {
			goto disable_vddio_reg;
		}
	}

	if (ts->ibb_reg) {
		retval = regulator_enable(ts->ibb_reg);
		if (retval < 0) {
			goto disable_lab_reg;
		}
	}

	return 0;

disable_ibb_reg:
	if (ts->ibb_reg)
		regulator_disable(ts->ibb_reg);

disable_lab_reg:
	if (ts->lab_reg)
		regulator_disable(ts->lab_reg);

disable_vddio_reg:
	if (ts->vddio_reg)
		regulator_disable(ts->vddio_reg);

exit:
	return retval;
}

static int nvt_gpio_config(struct nvt_ts_data *ts)
{
	int32_t ret = 0;

	if (gpio_is_valid(ts->reset_gpio)) {
		ret = gpio_request(ts->reset_gpio, "NVT-reset");
		if (ret)
			goto err_request_reset_gpio;
	}

	if (gpio_is_valid(ts->irq_gpio)) {
		ret = gpio_request_one(ts->irq_gpio, GPIOF_IN, "NVT-int");
		if (ret)
			goto err_request_irq_gpio;
	}

	return ret;

err_request_reset_gpio:
err_request_irq_gpio:
#if NVT_TOUCH_SUPPORT_HW_RST
	gpio_free(ts->reset_gpio);
err_request_reset_gpio:
#endif
	return ret;
}

static void nvt_gpio_deconfig(struct nvt_ts_data *ts)
{
	if (gpio_is_valid(ts->irq_gpio))
		gpio_free(ts->irq_gpio);
	if (gpio_is_valid(ts->reset_gpio))
		gpio_free(ts->reset_gpio);
}

static uint8_t nvt_fw_recovery(uint8_t *point_data)
{
	uint8_t i = 0;
	uint8_t detected = true;

	for (i = 1; i < 7; i++) {
		if (point_data[i] != 0x77) {
			detected = false;
			break;
		}
	}

	return detected;
}

static void nvt_ts_worker(struct work_struct *work)
{
	struct nvt_ts_data *ts = container_of(work, struct nvt_ts_data, irq_work);

	int32_t ret;
	int32_t i;
	int32_t finger_cnt;
	uint8_t point_data[POINT_DATA_LEN + 1] = { 0 };
	uint8_t input_id;
	uint8_t press_id[TOUCH_MAX_FINGER_NUM] = { 0 };
	uint32_t position;
	uint32_t input_x;
	uint32_t input_y;
	struct sched_param param = { .sched_priority = MAX_USER_RT_PRIO / 2 };

	sched_setscheduler(current, SCHED_RR, &param);

#if WAKEUP_GESTURE
	if (unlikely(bTouchIsAwake == 0)) {
		pm_wakeup_event(&ts->input_dev->dev, 5000);
	}
#endif

	mutex_lock(&ts->lock);

	if (ts->dev_pm_suspend) {
		ret = wait_for_completion_timeout(&ts->dev_pm_suspend_completion, msecs_to_jiffies(500));
		if (!ret) {
			goto XFER_ERROR;
		}
	}

	ret = CTP_I2C_READ(ts->client, I2C_FW_Address, point_data, POINT_DATA_LEN + 1);
	if (unlikely(ret < 0))
		goto XFER_ERROR;

	if (nvt_fw_recovery(point_data))
		goto XFER_ERROR;

#if WAKEUP_GESTURE
	if (unlikely(bTouchIsAwake == 0)) {
		input_id = (uint8_t)(point_data[1] >> 3);
		nvt_ts_wakeup_gesture_report(input_id, point_data);
		goto XFER_ERROR;
	}
#endif

	for (i = 0; i < ts->max_touch_num; i++) {
		position = 1 + 6 * i;
		input_id = (uint8_t)(point_data[position] >> 3);
		if ((input_id == 0) || (input_id > ts->max_touch_num))
			continue;

		if (likely(((point_data[position] & 0x07) == 0x01) ||
			   ((point_data[position] & 0x07) == 0x02))) {
			input_x = (uint32_t)(point_data[position + 1] << 4) +
				  (uint32_t)(point_data[position + 3] >> 4);
			input_y = (uint32_t)(point_data[position + 2] << 4) +
				  (uint32_t)(point_data[position + 3] & 0x0F);

			press_id[input_id - 1] = 1;
			input_mt_slot(ts->input_dev, input_id - 1);
			input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, true);

			input_report_abs(ts->input_dev, ABS_MT_POSITION_X, input_x);
			input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, input_y);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE, TOUCH_FORCE_NUM);

			finger_cnt++;
		}
	}

	for (i = 0; i < ts->max_touch_num; i++) {
		if (likely(press_id[i] != 1)) {
			input_mt_slot(ts->input_dev, i);
			input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
			input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);
		}
	}

	input_report_key(ts->input_dev, BTN_TOUCH, (finger_cnt > 0));
	input_sync(ts->input_dev);

XFER_ERROR:
	mutex_unlock(&ts->lock);
	return;
}

#if WAKEUP_GESTURE
#define EVENT_START				0
#define EVENT_WAKEUP_MODE_OFF			4
#define EVENT_WAKEUP_MODE_ON			5
#define EVENT_END				13

static void mi_switch_mode_work(struct work_struct *work)
{
	struct mi_mode_switch *ms = container_of(
			work, struct mi_mode_switch, switch_mode_work
	);
	struct nvt_ts_data *data = ms->nvt_data;
	unsigned char value = ms->mode;

	if (value >= EVENT_WAKEUP_MODE_OFF &&
		value <= EVENT_WAKEUP_MODE_ON)
		data->gesture_enabled = value - EVENT_WAKEUP_MODE_OFF;

	if (ms != NULL) {
		kfree(ms);
		ms = NULL;
	}
}

static int mi_input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	struct nvt_ts_data *data = input_get_drvdata(dev);
	struct mi_mode_switch *ms;

	if (type == EV_SYN && code == SYN_CONFIG) {

		if (value >= EVENT_START && value <= EVENT_END) {
			ms = kmalloc(sizeof(struct mi_mode_switch), GFP_ATOMIC);

			if (ms != NULL) {
				ms->nvt_data = data;
				ms->mode = (unsigned char)value;
				INIT_WORK(&ms->switch_mode_work, mi_switch_mode_work);
				schedule_work(&ms->switch_mode_work);
			} else {
				return -ENOMEM;
			}
		} else {
			return -EINVAL;
		}
	}

	return 0;
}
#endif

static irqreturn_t nvt_ts_work_func(int irq, void *data)
{
	struct nvt_ts_data *ts = data;

	queue_work(ts->coord_workqueue, &ts->irq_work);

	return IRQ_HANDLED;
}

void nvt_stop_crc_reboot(void)
{
	uint8_t buf[8] = { 0 };
	int32_t retry = 0;

	nvt_set_page(I2C_BLDR_Address, 0x1F64E);

	buf[0] = 0x4E;
	CTP_I2C_READ(ts->client, I2C_BLDR_Address, buf, 4);

	if ((buf[1] == 0xFC) ||
	    ((buf[1] == 0xFF) && (buf[2] == 0xFF) && (buf[3] == 0xFF))) {
		for (retry = 5; retry > 0; retry--) {
			buf[0] = 0x00;
			buf[1] = 0xA5;
			CTP_I2C_WRITE(ts->client, I2C_HW_Address, buf, 2);

			buf[0] = 0x00;
			buf[1] = 0xA5;
			CTP_I2C_WRITE(ts->client, I2C_HW_Address, buf, 2);
			msleep(1);

			nvt_set_page(I2C_BLDR_Address, 0x3F135);

			buf[0] = 0x35;
			buf[1] = 0xA5;
			CTP_I2C_WRITE(ts->client, I2C_BLDR_Address, buf, 2);

			nvt_set_page(I2C_BLDR_Address, 0x3F135);

			buf[0] = 0x35;
			buf[1] = 0x00;
			CTP_I2C_READ(ts->client, I2C_BLDR_Address, buf, 2);

			if (buf[1] == 0xA5)
				break;
		}
	}

	return;
}

static int8_t nvt_ts_check_chip_ver_trim(void)
{
	uint8_t buf[8] = { 0 };
	int32_t retry = 0;
	int32_t list = 0;
	int32_t i = 0;
	int32_t found_nvt_chip = 0;
	int32_t ret = -1;

	nvt_bootloader_reset();

	for (retry = 5; retry > 0; retry--) {
		nvt_sw_reset_idle();

		buf[0] = 0x00;
		buf[1] = 0x35;
		CTP_I2C_WRITE(ts->client, I2C_HW_Address, buf, 2);
		msleep(10);

		nvt_set_page(I2C_BLDR_Address, 0x1F64E);

		buf[0] = 0x4E;
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0x00;
		buf[4] = 0x00;
		buf[5] = 0x00;
		buf[6] = 0x00;
		CTP_I2C_READ(ts->client, I2C_BLDR_Address, buf, 7);

		if ((buf[1] == 0xFC) || ((buf[1] == 0xFF) && (buf[2] == 0xFF) &&
		    (buf[3] == 0xFF))) {
			nvt_stop_crc_reboot();
			continue;
		}

		for (list = 0; list < (sizeof(trim_id_table) /
		     sizeof(struct nvt_ts_trim_id_table)); list++) {
			found_nvt_chip = 0;

			for (i = 0; i < NVT_ID_BYTE_MAX; i++) {
				if (trim_id_table[list].mask[i]) {
					if (buf[i + 1] != trim_id_table[list].id[i])
						break;
				}
			}

			if (i == NVT_ID_BYTE_MAX)
				found_nvt_chip = 1;

			if (found_nvt_chip) {
				ts->mmap = trim_id_table[list].mmap;
				ts->carrier_system = trim_id_table[list].hwinfo->carrier_system;
				ret = 0;
				goto out;
			} else {
				ts->mmap = NULL;
				ret = -1;
			}
		}

		msleep(10);
	}

out:
	return ret;
}

#ifdef NVT_TOUCH_COUNT_DUMP
static ssize_t nvt_touch_suspend_notify_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", !bTouchIsAwake);
}
static DEVICE_ATTR(touch_suspend_notify, (S_IRUGO | S_IRGRP), nvt_touch_suspend_notify_show, NULL);
#endif

static int nvt_pinctrl_init(struct nvt_ts_data *nvt_data)
{
	int retval = 0;
	nvt_data->ts_pinctrl = devm_pinctrl_get(&nvt_data->client->dev);

	if (IS_ERR_OR_NULL(nvt_data->ts_pinctrl)) {
		retval = PTR_ERR(nvt_data->ts_pinctrl);
		goto err_pinctrl_get;
	}

	nvt_data->pinctrl_state_active = pinctrl_lookup_state(
			nvt_data->ts_pinctrl, PINCTRL_STATE_ACTIVE
		);

	if (IS_ERR_OR_NULL(nvt_data->pinctrl_state_active)) {
		retval = PTR_ERR(nvt_data->pinctrl_state_active);
		goto err_pinctrl_lookup;
	}

	nvt_data->pinctrl_state_suspend = pinctrl_lookup_state(
			nvt_data->ts_pinctrl, PINCTRL_STATE_SUSPEND
		);

	if (IS_ERR_OR_NULL(nvt_data->pinctrl_state_suspend)) {
		retval = PTR_ERR(nvt_data->pinctrl_state_suspend);
		goto err_pinctrl_lookup;
	}

	return 0;
err_pinctrl_lookup:
	devm_pinctrl_put(nvt_data->ts_pinctrl);
err_pinctrl_get:
	nvt_data->ts_pinctrl = NULL;
	return retval;
}

static int32_t nvt_ts_probe(struct i2c_client *client,
			    const struct i2c_device_id *id)
{
	int32_t ret = 0;
#if WAKEUP_GESTURE
	int32_t retry = 0;
#endif

	char *tp_maker = NULL;
	ts = kmalloc(sizeof(struct nvt_ts_data), GFP_KERNEL);
	if (ts == NULL)
		return -ENOMEM;

	ts->client = client;
	i2c_set_clientdata(client, ts);

	nvt_parse_dt(&client->dev);

	ret = nvt_pinctrl_init(ts);
	if (!ret && ts->ts_pinctrl) {
		ret = pinctrl_select_state(ts->ts_pinctrl, ts->pinctrl_state_active);
	}

	ret = nvt_gpio_config(ts);
	if (ret)
		goto err_gpio_config_failed;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		ret = -ENODEV;
		goto err_check_functionality_failed;
	}

	mutex_init(&ts->lock);
	mutex_init(&ts->xbuf_lock);

	msleep(10);

	ret = nvt_ts_check_chip_ver_trim();
	if (ret) {
		ret = -EINVAL;
		goto err_chipvertrim_failed;
	}

	nvt_bootloader_reset();
	nvt_check_fw_reset_state(RESET_STATE_INIT);
	nvt_get_fw_info();

	ts->input_dev = input_allocate_device();
	if (ts->input_dev == NULL) {
		ret = -ENOMEM;
		goto err_input_dev_alloc_failed;
	}

	ts->max_touch_num = TOUCH_MAX_FINGER_NUM;
	ts->int_trigger_type = INT_TRIGGER_TYPE;

	ts->input_dev->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS);
	ts->input_dev->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);
	ts->input_dev->propbit[0] = BIT(INPUT_PROP_DIRECT);

	input_mt_init_slots(ts->input_dev, ts->max_touch_num, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_PRESSURE, 0, TOUCH_FORCE_NUM, 0, 0);

#if TOUCH_MAX_FINGER_NUM > 1
	input_set_abs_params(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_X, 0, ts->abs_x_max, 0, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_Y, 0, ts->abs_y_max, 0, 0);
#endif

#if WAKEUP_GESTURE
	for (retry = 0; retry < (sizeof(gesture_key_array) /
	     sizeof(gesture_key_array[0])); retry++)
		input_set_capability(ts->input_dev, EV_KEY, gesture_key_array[retry]);

#ifdef CONFIG_TOUCHSCREEN_COMMON
	ret = tp_common_set_double_tap_ops(&double_tap_ops);
#endif
#endif

	sprintf(ts->phys, "input/ts");
	ts->input_dev->name = NVT_TS_NAME;
	ts->input_dev->phys = ts->phys;
	ts->input_dev->id.bustype = BUS_I2C;
#if WAKEUP_GESTURE
	ts->input_dev->event = mi_input_event;
	input_set_drvdata(ts->input_dev, ts);
#endif

	ret = input_register_device(ts->input_dev);
	if (ret)
		goto err_input_register_device_failed;

	nvt_get_reg(ts, true);

	//---set int-pin & request irq---
	client->irq = gpio_to_irq(ts->irq_gpio);
	if (client->irq) {
		ts->irq_enabled = true;
		ret = request_threaded_irq(client->irq, NULL, nvt_ts_work_func,
					   ts->int_trigger_type | IRQF_ONESHOT,
					   NVT_I2C_NAME, ts);
		if (ret != 0)
			goto err_int_request_failed;
		else
			nvt_irq_enable(false);
	}

	ts->fw_name = nvt_get_config(ts);
	tp_maker = kzalloc(20, GFP_KERNEL);

	if (tp_maker != NULL) {
		kfree(tp_maker);
		tp_maker = NULL;
	}

	ts->dbclick_count = 0;

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 1);
#endif
	ts->dev_pm_suspend = false;
	init_completion(&ts->dev_pm_suspend_completion);

#if BOOT_UPDATE_FIRMWARE
	nvt_fwu_wq = alloc_workqueue("nvt_fwu_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!nvt_fwu_wq) {
		ret = -ENOMEM;
		goto err_create_nvt_fwu_wq_failed;
	}
	INIT_DELAYED_WORK(&ts->nvt_fwu_work, Boot_Update_Firmware);
	queue_delayed_work(nvt_fwu_wq, &ts->nvt_fwu_work, msecs_to_jiffies(14000));
#endif

	ts->coord_workqueue = alloc_workqueue("nvt_ts_workqueue", WQ_HIGHPRI, 0);
	if (!ts->coord_workqueue) {
		ret = -ENOMEM;
		goto err_create_nvt_ts_workqueue_failed;
	}
	INIT_WORK(&ts->irq_work, nvt_ts_worker);

	ts->fb_notif.notifier_call = nvt_fb_notifier_callback;
	ret = fb_register_client(&ts->fb_notif);
	if (ret)
		goto err_register_fb_notif_failed;

#ifdef NVT_TOUCH_COUNT_DUMP
	if (ts->nvt_tp_class == NULL)
		ts->nvt_tp_class = class_create(THIS_MODULE, "touch");

	ts->nvt_touch_dev = device_create(ts->nvt_tp_class, NULL, 0x62, ts, "touch_suspend_notify");

	if (IS_ERR(ts->nvt_touch_dev)) {
		goto err_register_tp_class;
	}

	dev_set_drvdata(ts->nvt_touch_dev, ts);
	ret = sysfs_create_file(&ts->nvt_touch_dev->kobj, &dev_attr_touch_suspend_notify.attr);

	if (ret) {
		goto err_register_tp_class;
	}
#endif

	bTouchIsAwake = 1;
	nvt_irq_enable(true);

	return 0;

	fb_unregister_client(&ts->fb_notif);

#ifdef NVT_TOUCH_COUNT_DUMP
err_register_tp_class:
	device_destroy(ts->nvt_tp_class, 0x62);
	class_destroy(ts->nvt_tp_class);
	ts->nvt_tp_class = NULL;
#endif
err_register_fb_notif_failed:
err_create_nvt_ts_workqueue_failed:
	if (ts->coord_workqueue)
		destroy_workqueue(ts->coord_workqueue);
#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
err_create_nvt_fwu_wq_failed:
#endif
#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif
	free_irq(client->irq, ts);
err_int_request_failed:
	input_unregister_device(ts->input_dev);
	ts->input_dev = NULL;
err_input_register_device_failed:
	if (ts->input_dev) {
		input_free_device(ts->input_dev);
		ts->input_dev = NULL;
	}
err_input_dev_alloc_failed:
err_chipvertrim_failed:
	mutex_destroy(&ts->xbuf_lock);
	mutex_destroy(&ts->lock);
err_check_functionality_failed:
	nvt_gpio_deconfig(ts);
err_gpio_config_failed:
	i2c_set_clientdata(client, NULL);
	if (ts) {
		kfree(ts);
		ts = NULL;
	}
	return ret;
}

static int32_t nvt_ts_remove(struct i2c_client *client)
{
	if (ts->coord_workqueue)
		destroy_workqueue(ts->coord_workqueue);

	fb_unregister_client(&ts->fb_notif);

#ifdef NVT_TOUCH_COUNT_DUMP
	if (ts->dump_click_count && !ts->current_clicknum_file) {
		kfree(ts->current_clicknum_file);
		ts->current_clicknum_file = NULL;
	}

	sysfs_remove_file(&ts->nvt_touch_dev->kobj,
			  &dev_attr_touch_suspend_notify.attr);
	device_destroy(ts->nvt_tp_class, 0x62);
	class_destroy(ts->nvt_tp_class);
	ts->nvt_tp_class = NULL;
#endif

#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif

	nvt_get_reg(ts, false);
	nvt_irq_enable(false);
	free_irq(client->irq, ts);

	mutex_destroy(&ts->xbuf_lock);
	mutex_destroy(&ts->lock);

	nvt_gpio_deconfig(ts);

	if (ts->input_dev) {
		input_unregister_device(ts->input_dev);
		ts->input_dev = NULL;
	}

	i2c_set_clientdata(client, NULL);

	if (ts) {
		kfree(ts);
		ts = NULL;
	}

	return 0;
}

static void nvt_ts_shutdown(struct i2c_client *client)
{
	nvt_irq_enable(false);

	fb_unregister_client(&ts->fb_notif);

#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif
}

static int32_t __always_inline nvt_ts_suspend(struct device *dev)
{
	uint8_t buf[4] = { 0 };
	uint32_t i = 0;

	if (!bTouchIsAwake)
		return 0;

#if !WAKEUP_GESTURE
	nvt_irq_enable(false);
#endif

	mutex_lock(&ts->lock);

	bTouchIsAwake = 0;

#if WAKEUP_GESTURE
		buf[0] = EVENT_MAP_HOST_CMD;
		buf[1] = 0x13;
		CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 2);

		enable_irq_wake(ts->client->irq);
#else // WAKEUP_GESTURE
	buf[0] = EVENT_MAP_HOST_CMD;
	buf[1] = 0x11;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 2);

	if (ts->ts_pinctrl) {
		ret = pinctrl_select_state(ts->ts_pinctrl,
			ts->pinctrl_state_suspend);
	}
#endif // WAKEUP_GESTURE

	mutex_unlock(&ts->lock);

	for (i = 0; i < ts->max_touch_num; i++) {
		input_mt_slot(ts->input_dev, i);
		input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
	}

	input_report_key(ts->input_dev, BTN_TOUCH, 0);
	input_sync(ts->input_dev);

	msleep(50);

	return 0;
}

static int32_t __always_inline nvt_ts_resume(struct device *dev)
{

	int ret = 0;

	if (bTouchIsAwake)
		return 0;

	mutex_lock(&ts->lock);

#if NVT_TOUCH_SUPPORT_HW_RST
	gpio_set_value(ts->reset_gpio, 1);
#endif

	nvt_bootloader_reset();
	if (nvt_check_fw_reset_state(RESET_STATE_REK)) {
		nvt_bootloader_reset();
		nvt_check_fw_reset_state(RESET_STATE_REK);
	}

	if ((ts->gesture_enabled && ts->gesture_disabled_when_resume) || !ts->gesture_enabled_when_resume) {
		enable_irq(ts->client->irq);

		if (ts->ts_pinctrl) {
			ret = pinctrl_select_state(ts->ts_pinctrl, ts->pinctrl_state_active);
		}
	}

#if !WAKEUP_GESTURE
	nvt_irq_enable(true);

	if (ts->ts_pinctrl) {
		ret = pinctrl_select_state(ts->ts_pinctrl,
			ts->pinctrl_state_active);
	}
#endif

	bTouchIsAwake = 1;

	mutex_unlock(&ts->lock);

	return 0;
}

static int __always_inline nvt_fb_notifier_callback(struct notifier_block *self,
						    unsigned long event, void *data)
{
	int *blank;
	struct nvt_ts_data *ts = container_of(self, struct nvt_ts_data, fb_notif);
	struct fb_event *evdata = data;

	if (evdata && evdata->data && mdss_panel_is_prim(evdata->info)) {
		blank = evdata->data;
		if (event == FB_EARLY_EVENT_BLANK) {
			if (*blank == FB_BLANK_POWERDOWN) {
				if (ts->gesture_enabled) {
					nvt_enable_reg(ts, true);
					ts->gesture_enabled_when_resume = true;
					ts->gesture_disabled_when_resume = false;
					mdss_panel_reset_skip_enable(true);
				}
				nvt_ts_suspend(&ts->client->dev);
				if (ts->tddi_tp_hw_reset && !ts->gesture_enabled) {
					gpio_direction_output(ts->reset_gpio, 0);
				}
#ifdef NVT_TOUCH_COUNT_DUMP
				sysfs_notify(&ts->nvt_touch_dev->kobj, NULL,
						 "touch_suspend_notify");
#endif
			} else if (*blank == FB_BLANK_UNBLANK) {
				if ((ts->gesture_enabled || !ts->gesture_disabled_when_resume) && ts->gesture_enabled_when_resume) {
					if (ts->tddi_tp_hw_reset)
						gpio_direction_output(ts->reset_gpio, 0);
					gpio_direction_output(ts->reset_tddi, 0);
					msleep(15);
					gpio_direction_output(ts->reset_tddi, 1);
					if (ts->tddi_tp_hw_reset)
						gpio_direction_output(ts->reset_gpio, 1);
					msleep(20);
				}
			}
		} else if (event == FB_EVENT_BLANK) {
			if (*blank == FB_BLANK_UNBLANK) {
				if ((ts->gesture_enabled || !ts->gesture_disabled_when_resume) && ts->gesture_enabled_when_resume) {
					mdss_panel_reset_skip_enable(false);
					nvt_enable_reg(ts, false);
				}
				if (ts->tddi_tp_hw_reset && !ts->gesture_enabled) {
					gpio_direction_output(ts->reset_gpio, 1);
				}
				nvt_ts_resume(&ts->client->dev);
#ifdef NVT_TOUCH_COUNT_DUMP
				sysfs_notify(&ts->nvt_touch_dev->kobj, NULL,
						 "touch_suspend_notify");
#endif
			}
		}
	}
	return 0;
}

static const struct i2c_device_id nvt_ts_id[] = {
	{ NVT_I2C_NAME, 0 },
	{}
};

#ifdef CONFIG_OF
static struct of_device_id nvt_match_table[] = {
	{ .compatible = "novatek,NVT-ts" },
	{}
};
#endif

#ifdef CONFIG_PM
static int nvt_pm_suspend(struct device *dev)
{
	if (device_may_wakeup(dev) && ts->gesture_enabled) {
		enable_irq_wake(ts->client->irq);
	}
	ts->dev_pm_suspend = true;
	reinit_completion(&ts->dev_pm_suspend_completion);

	return 0;

}

static int nvt_pm_resume(struct device *dev)
{
	if (device_may_wakeup(dev) && ts->gesture_enabled) {
		disable_irq_wake(ts->client->irq);
	}
	ts->dev_pm_suspend = false;
	complete(&ts->dev_pm_suspend_completion);

	return 0;
}
static const struct dev_pm_ops nvt_dev_pm_ops = {
	.suspend = nvt_pm_suspend,
	.resume = nvt_pm_resume,
};
#endif

static struct i2c_driver nvt_i2c_driver = {
	.probe		= nvt_ts_probe,
	.remove		= nvt_ts_remove,
	.shutdown	= nvt_ts_shutdown,
	.id_table	= nvt_ts_id,
	.driver = {
		.name	= NVT_I2C_NAME,
		.owner	= THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &nvt_dev_pm_ops,
#endif
#ifdef CONFIG_OF
		.of_match_table = nvt_match_table,
#endif
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

static int32_t __init nvt_driver_init(void)
{
	int32_t ret = 0;

	ret = i2c_add_driver(&nvt_i2c_driver);
	if (ret) {
		return ret;
	}

	return ret;
}
module_init(nvt_driver_init);

static void __exit nvt_driver_exit(void)
{
	i2c_del_driver(&nvt_i2c_driver);
}
module_exit(nvt_driver_exit);

MODULE_DESCRIPTION("Novatek Touchscreen Driver");
MODULE_LICENSE("GPL");

/*
 * This code was re-written by rsuntk <rissu.ntk@gmail.com>
 */

#ifndef __CDFINGER_FP__
#define __CDFINGER_FP__

/* -- Begin feature configurations -- */

#define SUPPORT_ID_NUM 0
#define POWER_GPIO 1
#define POWER_REGULATOR 0

/* -- Begin required struct -- */
typedef struct key_report {
	int key;
	int value;
} key_report_t;

struct cdfinger_key_map {
	unsigned int type;
	unsigned int code;
};

struct cdfingerfp_data {
	struct platform_device *cdfinger_dev;
	struct miscdevice *miscdev;
#if SUPPORT_ID_NUM
	u32 id_num;
	u8 chip_id;
	struct pinctrl *fps_pinctrl;
	struct pinctrl_state *fps_id_high;
#endif
	u32 irq_num;
	u32 reset_num;
#if POWER_GPIO
	u32 pwr_num;
#endif
#if POWER_REGULATOR
	struct regulator *vdd;
#endif
	struct fasync_struct *async_queue;
	struct wakeup_source *cdfinger_lock;
	struct notifier_block notifier;
	struct mutex buf_lock;
	struct input_dev *cdfinger_input;
	int irq_enable_status;
	bool wake_flag;
} *g_cdfingerfp_data;

/* -- cdfinger helper function -- */
static __always_inline void cdfinger_delay(int ms)
{
	if (ms <= 20)
		usleep_range(ms * 1000, ms * 1000 + 100);
	else
		msleep(ms);
}

static noinline __attribute__((cold)) 
void _cdfinger_log(const char *level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%s" "cdfinger_fp: %pV", level, &vaf);

	va_end(args);
}

#define cdfinger_info(fmt, ...) \
	do { _cdfinger_log(KERN_INFO, "%s: " fmt, __func__, ##__VA_ARGS__); } while (0)

#define cdfinger_err(fmt, ...) \
	do { _cdfinger_log(KERN_ERR, "%s: " fmt, __func__, ##__VA_ARGS__); } while (0)

#define cdfinger_dbg(fmt, ...) \
	do { _cdfinger_log(KERN_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__); } while (0)

#define cdfinger_dbg_enter() cdfinger_dbg("enter\n")

/* -- cdfinger IOCTL infra -- */
#define CDFINGER_IOCTL_MAGIC_NO 0xFB
#define CDFINGER_INIT _IOW(CDFINGER_IOCTL_MAGIC_NO, 0, uint8_t)
#define CDFINGER_GETIMAGE _IOW(CDFINGER_IOCTL_MAGIC_NO, 1, uint8_t)
#define CDFINGER_INITERRUPT_MODE _IOW(CDFINGER_IOCTL_MAGIC_NO, 2, uint8_t)
#define CDFINGER_INITERRUPT_KEYMODE _IOW(CDFINGER_IOCTL_MAGIC_NO, 3, uint8_t)
#define CDFINGER_INITERRUPT_FINGERUPMODE _IOW(CDFINGER_IOCTL_MAGIC_NO, 4, uint8_t)
#define CDFINGER_RELEASE_WAKELOCK _IO(CDFINGER_IOCTL_MAGIC_NO, 5)
#define CDFINGER_CHECK_INTERRUPT _IO(CDFINGER_IOCTL_MAGIC_NO, 6)
#define CDFINGER_SET_SPI_SPEED _IOW(CDFINGER_IOCTL_MAGIC_NO, 7, uint32_t)
#define CDFINGER_REPORT_KEY_LEGACY _IOW(CDFINGER_IOCTL_MAGIC_NO, 10, uint8_t)
#define CDFINGER_POWERDOWN _IO(CDFINGER_IOCTL_MAGIC_NO, 11)
#define CDFINGER_GETID _IO(CDFINGER_IOCTL_MAGIC_NO, 12)

#define CDFINGER_INIT_GPIO _IO(CDFINGER_IOCTL_MAGIC_NO, 20)
#define CDFINGER_INIT_IRQ _IO(CDFINGER_IOCTL_MAGIC_NO, 21)
#define CDFINGER_POWER_ON _IO(CDFINGER_IOCTL_MAGIC_NO, 22)
#define CDFINGER_RESET _IO(CDFINGER_IOCTL_MAGIC_NO, 23)
#define CDFINGER_POWER_OFF _IO(CDFINGER_IOCTL_MAGIC_NO, 24)
#define CDFINGER_RELEASE_DEVICE _IO(CDFINGER_IOCTL_MAGIC_NO, 25)

#define CDFINGER_DISABLE_IRQ _IO(CDFINGER_IOCTL_MAGIC_NO, 13)
#define CDFINGER_HW_RESET _IOW(CDFINGER_IOCTL_MAGIC_NO, 14, uint8_t)
#define CDFINGER_GET_STATUS _IO(CDFINGER_IOCTL_MAGIC_NO, 15)
#define CDFINGER_REPORT_KEY _IOW(CDFINGER_IOCTL_MAGIC_NO, 19, key_report_t)
#define CDFINGER_NEW_KEYMODE _IOW(CDFINGER_IOCTL_MAGIC_NO, 37, uint8_t)
#define CDFINGER_WAKE_LOCK _IOW(CDFINGER_IOCTL_MAGIC_NO, 26, uint8_t)
#define CDFINGER_ENABLE_IRQ _IOW(CDFINGER_IOCTL_MAGIC_NO, 27, uint8_t)

/* -- Key value for event -- */
#define CF_NAV_INPUT_UP 600
#define CF_NAV_INPUT_DOWN 601
#define CF_NAV_INPUT_LEFT 602
#define CF_NAV_INPUT_RIGHT 603
#define CF_NAV_INPUT_CLICK 604
#define CF_NAV_INPUT_DOUBLE_CLICK KEY_VOLUMEUP
#define CF_NAV_INPUT_LONG_PRESS 605

#define CF_KEY_INPUT_HOME KEY_HOME
#define CF_KEY_INPUT_MENU KEY_MENU
#define CF_KEY_INPUT_BACK KEY_BACK
#define CF_KEY_INPUT_POWER KEY_POWER
#define CF_KEY_INPUT_CAMERA KEY_CAMERA

#endif // __CDFINGER_FP__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/errno.h>
#include <linux/spi/spi.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/pm_wakeup.h>
#include <linux/kthread.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/spi/spidev.h>
#include <linux/semaphore.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/input.h>
#include <linux/signal.h>
#include <linux/gpio.h>
#include <linux/mm.h>
#include <linux/of_gpio.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/of_irq.h>
#include <linux/regulator/consumer.h>
#include <linux/fb.h>
#include <linux/notifier.h>

#include "cdfingerfp.h"

#define DEVICE_NAME "fpsdev0"
#define INPUT_DEVICE_NAME "cdfinger_input"

static bool isInKeyMode = false; // key mode
static bool screen_status = true; // screen on
static bool irq_initialized = false;

static struct cdfinger_key_map maps[] = {
	{ EV_KEY, CF_KEY_INPUT_HOME },
	{ EV_KEY, CF_KEY_INPUT_MENU },
	{ EV_KEY, CF_KEY_INPUT_BACK },
	{ EV_KEY, CF_KEY_INPUT_POWER },
	{ EV_KEY, CF_NAV_INPUT_UP },
	{ EV_KEY, CF_NAV_INPUT_DOWN },
	{ EV_KEY, CF_NAV_INPUT_RIGHT },
	{ EV_KEY, CF_NAV_INPUT_LEFT },
	{ EV_KEY, CF_KEY_INPUT_CAMERA },
	{ EV_KEY, CF_NAV_INPUT_CLICK },
	{ EV_KEY, CF_NAV_INPUT_DOUBLE_CLICK },
	{ EV_KEY, CF_NAV_INPUT_LONG_PRESS },
};

static int cdfinger_init_gpio(struct cdfingerfp_data *cdfinger)
{
	int err;

	cdfinger_dbg_enter();

#if POWER_GPIO
	if (!gpio_is_valid(cdfinger->pwr_num)) {
		cdfinger_err("invalid pwr gpio\n");
		return -EIO;
	}
	err = gpio_request(cdfinger->pwr_num, "cdfinger-pwr");
	if (err) {
		cdfinger_err("failed to request pwr gpio: %d\n", err);
		return err;
	}
#endif

	if (!gpio_is_valid(cdfinger->reset_num)) {
		cdfinger_err("invalid reset gpio\n");
		err = -EIO;
		goto err_pwr;
	}
	err = gpio_request(cdfinger->reset_num, "cdfinger-reset");
	if (err) {
		cdfinger_err("failed to request reset gpio: %d\n", err);
		goto err_pwr;
	}
	gpio_direction_output(cdfinger->reset_num, 1);

	if (!gpio_is_valid(cdfinger->irq_num)) {
		cdfinger_err("invalid irq gpio\n");
		err = -EIO;
		goto err_reset;
	}
	err = gpio_request(cdfinger->irq_num, "cdfinger-irq");
	if (err) {
		cdfinger_err("failed to request irq gpio: %d\n", err);
		goto err_reset;
	}
	gpio_direction_input(cdfinger->irq_num);

	return 0;

err_reset:
	gpio_free(cdfinger->reset_num);
err_pwr:
#if POWER_GPIO
	gpio_free(cdfinger->pwr_num);
#endif
	return err;
}

static int cdfinger_free_gpio(struct cdfingerfp_data *cdfinger)
{
	int err = 0;

	cdfinger_dbg_enter();

	if (gpio_is_valid(cdfinger->irq_num)) {
		gpio_free(cdfinger->irq_num);
		free_irq(gpio_to_irq(cdfinger->irq_num), (void *)cdfinger);
	}

	if (gpio_is_valid(cdfinger->reset_num)) {
		gpio_free(cdfinger->reset_num);
	}

#if POWER_GPIO
	if (gpio_is_valid(cdfinger->pwr_num)) {
		gpio_free(cdfinger->pwr_num);
	}
#endif
	return err;
}

static void cdfinger_reset(struct cdfingerfp_data *pdata, int ms)
{
	gpio_set_value(pdata->reset_num, 1);
	cdfinger_delay(ms);
	gpio_set_value(pdata->reset_num, 0);
	cdfinger_delay(ms);
	gpio_set_value(pdata->reset_num, 1);
	cdfinger_delay(ms);
}

static int cdfinger_parse_dts(struct device *dev,
			      struct cdfingerfp_data *cdfinger)
{
	int err = 0;

	if (unlikely(!cdfinger || !dev->of_node))
		return -EINVAL;

	cdfinger_dbg_enter();

#if POWER_GPIO
	cdfinger->pwr_num = of_get_named_gpio(dev->of_node, "cdfinger,gpio_vdd", 0);
	if (cdfinger->pwr_num < 0) {
		cdfinger_err("Failed to get vdd gpio: %d\n", cdfinger->pwr_num);
		return cdfinger->pwr_num;
	}
#endif
	cdfinger->reset_num = of_get_named_gpio(dev->of_node, "cdfinger,reset_gpio", 0);
	if (cdfinger->reset_num < 0) {
		cdfinger_err("Failed to get reset gpio: %d\n", cdfinger->reset_num);
		return cdfinger->reset_num;
	}

	cdfinger->irq_num = of_get_named_gpio(dev->of_node, "cdfinger,irq_gpio", 0);
	if (cdfinger->irq_num < 0) {
		cdfinger_err("Failed to get irq gpio: %d\n", cdfinger->irq_num);
		return cdfinger->irq_num;
	}

#if POWER_REGULATOR
	cdfinger->vdd = regulator_get(dev, "vdd");
	if (IS_ERR(cdfinger->vdd)) {
		err = PTR_ERR(cdfinger->vdd);
		cdfinger_err("Failed to get vdd regulator: %d\n", err);
		return err;
	}
#endif

#if SUPPORT_ID_NUM
	cdfinger->id_num = of_get_named_gpio(dev->of_node, "cdfinger,id_gpio", 0);
	if (cdfinger->id_num < 0) {
		cdfinger_err("Failed to get id gpio: %d\n", cdfinger->id_num);
		return cdfinger->id_num;
	}

	cdfinger->fps_pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(cdfinger->fps_pinctrl)) {
		err = PTR_ERR(cdfinger->fps_pinctrl);
		cdfinger_err("Failed to get fps pinctrl: %d\n", err);
		return err;
	}
#endif

	return 0;
}

static int cdfinger_power_on(struct cdfingerfp_data *pdata)
{
	int ret = 0;
#if POWER_GPIO
	gpio_direction_output(pdata->pwr_num, 1);
#endif
#if POWER_REGULATOR
	regulator_set_voltage(pdata->vdd, 0, 2800000);
	ret = regulator_enable(pdata->vdd);
	if (ret) {
		cdfinger_err("enable regulato fail\n");
		return ret;
	}
#endif
	msleep(10);
	return ret;
}

static int cdfinger_power_off(struct cdfingerfp_data *pdata)
{
#if POWER_GPIO
	gpio_direction_output(pdata->pwr_num, 0);
#endif
#if POWER_REGULATOR
	regulator_disable(pdata->vdd);
#endif
	mdelay(1);
	return 0;
}

static int cdfinger_open(struct inode *inode, struct file *file)
{
	cdfinger_dbg_enter();
	file->private_data = g_cdfingerfp_data;
	return 0;
}

static int cdfinger_async_fasync(int fd, struct file *file, int mode)
{
	struct cdfingerfp_data *cdfingerfp = g_cdfingerfp_data;

	if (!cdfingerfp)
		return -EIO;

	return fasync_helper(fd, file, mode, &cdfingerfp->async_queue);
}

static int cdfinger_release(struct inode *inode, struct file *file)
{
	struct cdfingerfp_data *cdfingerfp = file->private_data;

	cdfinger_dbg_enter();

	if (!cdfingerfp)
		return -EIO;

	cdfinger_async_fasync(-1, file, 0);
	file->private_data = NULL;
	return 0;
}

static void cdfinger_wake_lock(struct cdfingerfp_data *pdata, int arg)
{
	if (arg) {
		if (!pdata->wake_flag) {
			__pm_stay_awake(pdata->cdfinger_lock);
			pdata->wake_flag = true;
		}
	} else {
		if (pdata->wake_flag) {
			__pm_relax(pdata->cdfinger_lock);
			pdata->wake_flag = false;
		}
	}
}

static void cdfinger_async_report(void)
{
	struct cdfingerfp_data *cdfingerfp = g_cdfingerfp_data;
	kill_fasync(&cdfingerfp->async_queue, SIGIO, POLL_IN);
}

static irqreturn_t cdfinger_eint_handler(int irq, void *dev_id)
{
	struct cdfingerfp_data *pdata = g_cdfingerfp_data;

	if (unlikely(!pdata))
		goto skip;
	if (pdata->irq_enable_status == 1) {
		cdfinger_wake_lock(pdata, 1);
		cdfinger_async_report();
	}
skip:
	return IRQ_HANDLED;
}

static int cdfinger_init_irq(struct cdfingerfp_data *pdata)
{
	int error = 0;

	cdfinger_dbg_enter();

	if (irq_initialized) {
		cdfinger_err("irq already initialized\n");
		return 0;
	}

	error = request_threaded_irq(gpio_to_irq(pdata->irq_num),
				     cdfinger_eint_handler, NULL,
				     IRQF_TRIGGER_RISING, "cdfinger_eint",
				     (void *)pdata);
	if (error < 0) {
		cdfinger_err("irq init err\n");
		return error;
	}

	enable_irq_wake(gpio_to_irq(pdata->irq_num));
	irq_initialized = true;
	pdata->irq_enable_status = 1;
	return error;
}

static int cdfinger_irq_controller(struct cdfingerfp_data *pdata, bool Onoff)
{
	if (!irq_initialized) {
		cdfinger_err("irq not requested!\n");
		return -1;
	}

	if (Onoff && pdata->irq_enable_status == 0) {		
		enable_irq(gpio_to_irq(pdata->irq_num));
		enable_irq_wake(gpio_to_irq(pdata->irq_num));
		pdata->irq_enable_status = 1;
		return 0;
	}

	if (!Onoff && pdata->irq_enable_status == 1) {		
		disable_irq(gpio_to_irq(pdata->irq_num));
		disable_irq_wake(gpio_to_irq(pdata->irq_num));
		pdata->irq_enable_status = 0;
		return 0;
	}

	return -1;
}

static int cdfinger_report_key(struct cdfingerfp_data *cdfinger,
			       unsigned long arg)
{
	key_report_t report = { 0 };
	if (copy_from_user(&report, (key_report_t *)arg, sizeof(key_report_t))) {
		cdfinger_err("err\n");
		return -EFAULT;
	}

	switch (report.key) {
	case KEY_UP:
		report.key = CF_NAV_INPUT_UP;
		break;
	case KEY_DOWN:
		report.key = CF_NAV_INPUT_DOWN;
		break;
	case KEY_RIGHT:
		report.key = CF_NAV_INPUT_RIGHT;
		break;
	case KEY_LEFT:
		report.key = CF_NAV_INPUT_LEFT;
		break;
	case KEY_F11:
		report.key = CF_NAV_INPUT_CLICK;
		break;
	case KEY_F12:
		report.key = CF_NAV_INPUT_LONG_PRESS;
		break;
	default:
		break;
	}

	input_report_key(cdfinger->cdfinger_input, report.key, !!report.value);
	input_sync(cdfinger->cdfinger_input);
	return 0;
}

static long cdfinger_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	int err = 0;
	struct cdfingerfp_data *cdfinger = filp->private_data;

	if (unlikely(!cdfinger)) {
		cdfinger_err("failed to get private_data\n");
		return -EINVAL;
	}

	if (mutex_lock_interruptible(&cdfinger->buf_lock)) {
		cdfinger_err("received interruption!\n");
		return -ERESTARTSYS;
	}

	switch (cmd) {
	case CDFINGER_INIT_GPIO:
		err = cdfinger_init_gpio(cdfinger);
		break;
	case CDFINGER_INIT_IRQ:
		err = cdfinger_init_irq(cdfinger);
#if SUPPORT_ID_NUM
		cdfinger->chip_id = 0x98;
#endif
		break;
	case CDFINGER_RELEASE_DEVICE:
		irq_initialized = 0;
		cdfinger_free_gpio(cdfinger);
#if SUPPORT_ID_NUM
		cdfinger->chip_id = 0x00;
#endif
		misc_deregister(cdfinger->miscdev);
		break;
	case CDFINGER_WAKE_LOCK:
		cdfinger_wake_lock(cdfinger, arg);
		break;
	case CDFINGER_POWER_ON:
		err = cdfinger_power_on(cdfinger);
		break;
	case CDFINGER_POWER_OFF:
		err = cdfinger_power_off(cdfinger);
		break;
	case CDFINGER_RESET:
		cdfinger_reset(cdfinger, 1);
		break;
	case CDFINGER_INITERRUPT_MODE:
		isInKeyMode = true; // not key mode
		cdfinger_reset(cdfinger, 1);
		break;
	case CDFINGER_NEW_KEYMODE:
		isInKeyMode = false;
		cdfinger_reset(cdfinger, 1);
		break;
	case CDFINGER_HW_RESET:
		cdfinger_reset(cdfinger, arg);
		break;
	case CDFINGER_GET_STATUS:
		err = (int)screen_status;
		break;
	case CDFINGER_ENABLE_IRQ:
		err = cdfinger_irq_controller(cdfinger, arg);
		break;
	case CDFINGER_REPORT_KEY:
		err = cdfinger_report_key(cdfinger, arg);
		break;
	case CDFINGER_GETID:
#if SUPPORT_ID_NUM
		err = cdfinger->chip_id;
#endif
		break;
	default:
		err = -ENOTTY;
		break;
	}

	mutex_unlock(&cdfinger->buf_lock);
	return err;
}

static int cdfinger_fb_notifier_callback(struct notifier_block *self,
					 unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int blank_mode;
	bool status = false;

	if (event != FB_EVENT_BLANK || !evdata || !evdata->data)
		return 0;

	blank_mode = *(int *)evdata->data;

	switch (blank_mode) {
	case FB_BLANK_UNBLANK:
		status = true;
		break;
	case FB_BLANK_POWERDOWN:
		status = false;
		break;
	default:
		return 0;
	}

	mutex_lock(&g_cdfingerfp_data->buf_lock);
	screen_status = status;
	if (!isInKeyMode)
		cdfinger_async_report();
	mutex_unlock(&g_cdfingerfp_data->buf_lock);

	return 0;
}

#if SUPPORT_ID_NUM
static int cdfinger_support_id(struct cdfingerfp_data *cdfinger)
{
	int val, err;

	cdfinger_dbg_enter();

	cdfinger->fps_id_high = pinctrl_lookup_state(cdfinger->fps_pinctrl, "cdfinger_id_pin");
	if (IS_ERR(cdfinger->fps_id_high)) {
		cdfinger_err("Failed to lookup pinctrl state\n");
		return PTR_ERR(cdfinger->fps_id_high);
	}

	err = pinctrl_select_state(cdfinger->fps_pinctrl, cdfinger->fps_id_high);
	if (err) {
		cdfinger_err("Failed to select pinctrl state: %d\n", err);
		return err;
	}

	if (!gpio_is_valid(cdfinger->id_num)) {
		cdfinger_err("invalid gpio\n");
		return -EINVAL;
	}

	err = gpio_request(cdfinger->id_num, "cdfinger-id");
	if (err) {
		cdfinger_err("Unable to request GPIO: %d\n", err);
		return err;
	}

	gpio_direction_input(cdfinger->id_num);
	val = gpio_get_value(cdfinger->id_num);

	gpio_free(cdfinger->id_num);
	
	cdfinger_dbg("hardware id value: %d\n", val);
	return val;
}
#endif

static const struct file_operations cdfinger_fops = {
	.owner = THIS_MODULE,
	.open = cdfinger_open,
	.unlocked_ioctl = cdfinger_ioctl,
	.release = cdfinger_release,
	.fasync = cdfinger_async_fasync,
#ifdef CONFIG_COMPAT
	.compat_ioctl = cdfinger_ioctl,
#endif
};

static struct miscdevice st_cdfinger_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &cdfinger_fops,
};

static int cdfinger_probe(struct platform_device *pdev)
{
	struct cdfingerfp_data *cdfingerdev;
	struct device *dev = &pdev->dev;
	int status;
	int i;

	cdfinger_dbg_enter();

	cdfingerdev = devm_kzalloc(dev, sizeof(*cdfingerdev), GFP_KERNEL);
	if (!cdfingerdev)
		return -ENOMEM;

	cdfingerdev->cdfinger_dev = pdev;

	status = cdfinger_parse_dts(dev, cdfingerdev);
	if (unlikely(status)) {
		cdfinger_err("parse dts failed: %d\n", status);
		return status;
	}

#if SUPPORT_ID_NUM
	status = cdfinger_support_id(cdfingerdev);
	if (status != 1) {
		cdfinger_err("hardware id mismatch: %d\n", status);
		return -ENODEV;
	}
#endif

	mutex_init(&cdfingerdev->buf_lock);
	cdfingerdev->cdfinger_lock = wakeup_source_register(dev, "cdfinger_wakelock");
	if (!cdfingerdev->cdfinger_lock) {
		status = -ENOMEM;
		goto err_mutex;
	}

	status = misc_register(&st_cdfinger_dev);
	if (status) {
		cdfinger_err("Cannot register misc device: %d\n", status);
		goto err_wakeup;
	}
	cdfingerdev->miscdev = &st_cdfinger_dev;

	cdfingerdev->cdfinger_input = devm_input_allocate_device(dev);
	if (!cdfingerdev->cdfinger_input) {
		cdfinger_err("Cannot allocate input device.\n");
		status = -ENOMEM;
		goto err_misc;
	}

	cdfingerdev->cdfinger_input->name = INPUT_DEVICE_NAME;
	for (i = 0; i < ARRAY_SIZE(maps); i++) {
		input_set_capability(cdfingerdev->cdfinger_input, maps[i].type,
				     maps[i].code);
	}

	status = input_register_device(cdfingerdev->cdfinger_input);
	if (status) {
		cdfinger_err("Cannot register input device: %d\n", status);
		goto err_misc;
	}

	cdfingerdev->notifier.notifier_call = cdfinger_fb_notifier_callback;
	status = fb_register_client(&cdfingerdev->notifier);
	if (status) {
		cdfinger_err("Register fb notifier failed: %d\n", status);
		goto err_input;
	}

	g_cdfingerfp_data = cdfingerdev;
	platform_set_drvdata(pdev, cdfingerdev);

	return 0;

err_input:
err_misc:
	misc_deregister(&st_cdfinger_dev);
err_wakeup:
	wakeup_source_unregister(cdfingerdev->cdfinger_lock);
err_mutex:
	mutex_destroy(&cdfingerdev->buf_lock);
	return status;
}

static const struct of_device_id cdfinger_of_match[] = {
	{ .compatible = "cdfinger,fps998e" },
	{ .compatible = "cdfinger,fingerprint" },
	{},
};

static const struct platform_device_id cdfinger_id[] = {
	{ "cdfinger_fp", 0 },
	{},
};

static struct platform_driver cdfinger_driver = {
	.driver = {
		.name = "cdfinger_fp",
		.of_match_table = cdfinger_of_match,
	},
	.id_table = cdfinger_id,
	.probe = cdfinger_probe,
};

static int __init cdfinger_fp_init(void)
{
	return platform_driver_register(&cdfinger_driver);
}

static void __exit cdfinger_fp_exit(void)
{
	platform_driver_unregister(&cdfinger_driver);
}

module_init(cdfinger_fp_init);
module_exit(cdfinger_fp_exit);

MODULE_DESCRIPTION("cdfinger Driver");
MODULE_AUTHOR("cdfinger@cdfinger.com");
MODULE_LICENSE("GPL");
MODULE_ALIAS("cdfinger");

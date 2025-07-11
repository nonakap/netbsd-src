/* $NetBSD: fcu.c,v 1.6 2025/07/01 14:13:13 macallan Exp $ */

/*-
 * Copyright (c) 2018 Michael Lorenz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: fcu.c,v 1.6 2025/07/01 14:13:13 macallan Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/sysctl.h>

#include <dev/i2c/i2cvar.h>

#include <dev/sysmon/sysmonvar.h>

#include <dev/ofw/openfirm.h>

#include <macppc/dev/fancontrolvar.h>

#include "opt_fcu.h"

#ifdef FCU_DEBUG
#define DPRINTF printf
#else
#define DPRINTF if (0) printf
#endif

/* FCU registers, from OpenBSD's fcu.c */
#define FCU_FAN_FAIL	0x0b		/* fans states in bits 0<1-6>7 */
#define FCU_FAN_ACTIVE	0x0d
#define FCU_FANREAD(x)	0x11 + (x)*2
#define FCU_FANSET(x)	0x10 + (x)*2
#define FCU_PWM_FAIL	0x2b
#define FCU_PWM_ACTIVE	0x2d
#define FCU_PWMREAD(x)	0x30 + (x)*2


typedef struct _fcu_fan {
	int target;
	int reg;
	int base_rpm, max_rpm;
	int step;
	int duty;	/* for pwm fans */
} fcu_fan_t;

#define FCU_ZONE_CPU		0
#define FCU_ZONE_CASE		1
#define FCU_ZONE_DRIVEBAY	2
#define FCU_ZONE_COUNT		3

struct fcu_softc {
	device_t	sc_dev;
	i2c_tag_t	sc_i2c;
	i2c_addr_t	sc_addr;
	struct sysctlnode 	*sc_sysctl_me;
	struct sysmon_envsys	*sc_sme;
	envsys_data_t		sc_sensors[32];
	int			sc_nsensors;
	fancontrol_zone_t	sc_zones[FCU_ZONE_COUNT];
	fcu_fan_t		sc_fans[FANCONTROL_MAX_FANS];
	int			sc_nfans;
	lwp_t			*sc_thread;
	bool			sc_dying, sc_pwm;
	uint8_t			sc_eeprom0[160];
	uint8_t			sc_eeprom1[160];
};

static int	fcu_match(device_t, cfdata_t, void *);
static void	fcu_attach(device_t, device_t, void *);

static void	fcu_sensors_refresh(struct sysmon_envsys *, envsys_data_t *);
static void	fcu_configure_sensor(struct fcu_softc *, envsys_data_t *);

static bool is_cpu(const envsys_data_t *);
static bool is_case(const envsys_data_t *);
static bool is_drive(const envsys_data_t *);

static int fcu_set_rpm(void *, int, int);
static int fcu_get_rpm(void *, int);
static void fcu_adjust(void *);

CFATTACH_DECL_NEW(fcu, sizeof(struct fcu_softc),
    fcu_match, fcu_attach, NULL, NULL);

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "fcu" },
	DEVICE_COMPAT_EOL
};

static int
fcu_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;
	
	if (ia->ia_addr == 0x2f)
		return I2C_MATCH_ADDRESS_ONLY;
	
	return 0;
}

static void
fcu_attach(device_t parent, device_t self, void *aux)
{
	struct fcu_softc *sc = device_private(self);
	struct i2c_attach_args *ia = aux;
	int i;

	sc->sc_dev = self;
	sc->sc_i2c = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;

	aprint_naive("\n");
	aprint_normal(": Fan Control Unit\n");

	sysctl_createv(NULL, 0, NULL, (void *) &sc->sc_sysctl_me,
	    CTLFLAG_READWRITE,
	    CTLTYPE_NODE, device_xname(sc->sc_dev), NULL,
	    NULL, 0, NULL, 0,
	    CTL_MACHDEP, CTL_CREATE, CTL_EOL);

	if (get_cpuid(0, sc->sc_eeprom0) < 160) {
		/*
		 * XXX this should never happen, we depend on the EEPROM for
		 * calibration data to make sense of temperature and voltage
		 * sensors elsewhere, and fan parameters here.
		 */
		aprint_error_dev(self, "no EEPROM data for CPU 0\n");
		return;
	}

	/* init zones */
	sc->sc_zones[FCU_ZONE_CPU].name = "CPUs";
	sc->sc_zones[FCU_ZONE_CPU].filter = is_cpu;
	sc->sc_zones[FCU_ZONE_CPU].cookie = sc;
	sc->sc_zones[FCU_ZONE_CPU].get_rpm = fcu_get_rpm;
	sc->sc_zones[FCU_ZONE_CPU].set_rpm = fcu_set_rpm;
	sc->sc_zones[FCU_ZONE_CPU].Tmin = 50;
	sc->sc_zones[FCU_ZONE_CPU].Tmax = 85;
	sc->sc_zones[FCU_ZONE_CPU].nfans = 0;
	sc->sc_zones[FCU_ZONE_CASE].name = "Slots";
	sc->sc_zones[FCU_ZONE_CASE].filter = is_case;
	sc->sc_zones[FCU_ZONE_CASE].cookie = sc;
	sc->sc_zones[FCU_ZONE_CASE].Tmin = 50;
	sc->sc_zones[FCU_ZONE_CASE].Tmax = 75;
	sc->sc_zones[FCU_ZONE_CASE].nfans = 0;
	sc->sc_zones[FCU_ZONE_CASE].get_rpm = fcu_get_rpm;
	sc->sc_zones[FCU_ZONE_CASE].set_rpm = fcu_set_rpm;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].name = "Drivebays";
	sc->sc_zones[FCU_ZONE_DRIVEBAY].filter = is_drive;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].cookie = sc;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].get_rpm = fcu_get_rpm;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].set_rpm = fcu_set_rpm;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].Tmin = 30;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].Tmax = 50;
	sc->sc_zones[FCU_ZONE_DRIVEBAY].nfans = 0;

	sc->sc_sme = sysmon_envsys_create();
	sc->sc_sme->sme_name = device_xname(self);
	sc->sc_sme->sme_cookie = sc;
	sc->sc_sme->sme_refresh = fcu_sensors_refresh;

	sc->sc_sensors[0].units = ENVSYS_SFANRPM;
	sc->sc_sensors[1].state = ENVSYS_SINVALID;
	sc->sc_nfans = 0;

	/* round up sensors */
	int ch;

	sc->sc_nsensors = 0;
	ch = OF_child(ia->ia_cookie);
	if (ch == 0) {
		/* old style data, no individual nodes for fans, annoying */
		char loc[256], tp[256], descr[32], type[32];
		uint32_t reg_rpm = 0x10, reg_pwm = 0x32, reg;
		uint32_t id[16];
		int num, lidx = 0, tidx = 0;

		num = OF_getprop(ia->ia_cookie, "hwctrl-id", id, 64);
		OF_getprop(ia->ia_cookie, "hwctrl-location", loc, 1024);
		OF_getprop(ia->ia_cookie, "hwctrl-type", tp, 1024);
		while (num > 0) {
			envsys_data_t *s = &sc->sc_sensors[sc->sc_nsensors];

			s->state = ENVSYS_SINVALID;
			strcpy(descr, &loc[lidx]);
			strcpy(type, &tp[tidx]);
			if (strstr(type, "rpm") != NULL) {
				s->units = ENVSYS_SFANRPM;
				reg = reg_rpm;
				reg_rpm += 2;
			} else if (strstr(type, "pwm") != NULL) {
				s->units = ENVSYS_SFANRPM;
				reg = reg_pwm;
				reg_pwm += 2;
			} else goto skip;

			s->private = reg;
			strcpy(s->desc, descr);

			fcu_configure_sensor(sc, s);

			sysmon_envsys_sensor_attach(sc->sc_sme, s);
			sc->sc_nsensors++;
skip:
			lidx += strlen(descr) + 1;
			tidx += strlen(type) + 1;
			num -= 4;
		}
	} else {
		/* new style, with individual nodes */
		while (ch != 0) {
			char type[32], descr[32];
			uint32_t reg;

			envsys_data_t *s = &sc->sc_sensors[sc->sc_nsensors];

			s->state = ENVSYS_SINVALID;

			if (OF_getprop(ch, "device_type", type, 32) <= 0)
				goto next;

			if (strcmp(type, "fan-rpm-control") == 0) {
				s->units = ENVSYS_SFANRPM;
			} else if (strcmp(type, "fan-pwm-control") == 0) {
				/* XXX we get the type from the register number */
				s->units = ENVSYS_SFANRPM;
/* skip those for now since we don't really know how to interpret them */
#if 0
			} else if (strcmp(type, "power-sensor") == 0) {
				s->units = ENVSYS_SVOLTS_DC;
#endif
			} else if (strcmp(type, "gpi-sensor") == 0) {
				s->units = ENVSYS_INDICATOR;
			} else {
				/* ignore other types for now */
				goto next;
			}

			if (OF_getprop(ch, "reg", &reg, sizeof(reg)) <= 0)
				goto next;
			s->private = reg;

			if (OF_getprop(ch, "location", descr, 32) <= 0)
				goto next;
			strcpy(s->desc, descr);

			fcu_configure_sensor(sc, s);

			sysmon_envsys_sensor_attach(sc->sc_sme, s);
			sc->sc_nsensors++;
next:
			ch = OF_peer(ch);
		}
	}		
	sysmon_envsys_register(sc->sc_sme);

	/* setup sysctls for our zones etc. */
	for (i = 0; i < FCU_ZONE_COUNT; i++) {
		fancontrol_init_zone(&sc->sc_zones[i], sc->sc_sysctl_me);
	}

	sc->sc_dying = FALSE;
	kthread_create(PRI_NONE, 0, curcpu(), fcu_adjust, sc, &sc->sc_thread,
	    "fan control");
}

static void
fcu_configure_sensor(struct fcu_softc *sc, envsys_data_t *s)
{
	int have_eeprom1 = 1;

	if (get_cpuid(1, sc->sc_eeprom1) < 160)
		have_eeprom1 = 0;

	if (s->units == ENVSYS_SFANRPM) {
		fcu_fan_t *fan = &sc->sc_fans[sc->sc_nfans];
		uint8_t *eeprom = NULL;
		uint16_t rmin, rmax;

		if (strstr(s->desc, "CPU A") != NULL)
			eeprom = sc->sc_eeprom0;
		if (strstr(s->desc, "CPU B") != NULL) {
			/*
			 * XXX
			 * this should never happen
			 */
			if (have_eeprom1 == 0) {
				eeprom = sc->sc_eeprom0;
			} else
				eeprom = sc->sc_eeprom1;
		}

		fan->reg = s->private;
		fan->target = 0;
		fan->duty = 0x80;

		/* speed settings from EEPROM */
		if (strstr(s->desc, "PUMP") != NULL) {
			KASSERT(eeprom != NULL);
			memcpy(&rmin, &eeprom[0x54], 2);
			memcpy(&rmax, &eeprom[0x56], 2);
			fan->base_rpm = rmin;
			fan->max_rpm = rmax;
			fan->step = (rmax - rmin) / 30;
		} else if (strstr(s->desc, "INTAKE") != NULL) {
			KASSERT(eeprom != NULL);
			memcpy(&rmin, &eeprom[0x4c], 2);
			memcpy(&rmax, &eeprom[0x4e], 2);
			fan->base_rpm = rmin;
			fan->max_rpm = rmax;
			fan->step = (rmax - rmin) / 30;
		} else if (strstr(s->desc, "EXHAUST") != NULL) {
			KASSERT(eeprom != NULL);
			memcpy(&rmin, &eeprom[0x50], 2);
			memcpy(&rmax, &eeprom[0x52], 2);
			fan->base_rpm = rmin;
			fan->max_rpm = rmax;
			fan->step = (rmax - rmin) / 30;
		} else if (strstr(s->desc, "DRIVE") != NULL ) {
			fan->base_rpm = 1000;
			fan->max_rpm = 3000;
			fan->step = 100;
		} else {
			fan->base_rpm = 1000;
			fan->max_rpm = 3000;
			fan->step = 100;
		}
		DPRINTF("fan %s: %d - %d rpm, step %d\n",
		   s->desc, fan->base_rpm, fan->max_rpm, fan->step);

		/* now stuff them into zones */
		if (strstr(s->desc, "CPU") != NULL) {
			fancontrol_zone_t *z = &sc->sc_zones[FCU_ZONE_CPU];
			z->fans[z->nfans].num = sc->sc_nfans;
			z->fans[z->nfans].min_rpm = fan->base_rpm;
			z->fans[z->nfans].max_rpm = fan->max_rpm;
			z->fans[z->nfans].name = s->desc;
			z->nfans++;
		} else if ((strstr(s->desc, "BACKSIDE") != NULL) ||
			   (strstr(s->desc, "SLOT") != NULL))  {
			fancontrol_zone_t *z = &sc->sc_zones[FCU_ZONE_CASE];
			z->fans[z->nfans].num = sc->sc_nfans;
			z->fans[z->nfans].min_rpm = fan->base_rpm;
			z->fans[z->nfans].max_rpm = fan->max_rpm;
			z->fans[z->nfans].name = s->desc;
			z->nfans++;
		} else if (strstr(s->desc, "DRIVE") != NULL) {
			fancontrol_zone_t *z = &sc->sc_zones[FCU_ZONE_DRIVEBAY];
			z->fans[z->nfans].num = sc->sc_nfans;
			z->fans[z->nfans].min_rpm = fan->base_rpm;
			z->fans[z->nfans].max_rpm = fan->max_rpm;
			z->fans[z->nfans].name = s->desc;
			z->nfans++;
		}
		sc->sc_nfans++;
	}
}
static void
fcu_sensors_refresh(struct sysmon_envsys *sme, envsys_data_t *edata)
{
	struct fcu_softc *sc = sme->sme_cookie;
	uint8_t cmd;
	uint16_t data = 0;
	int error;

	if (edata->units == ENVSYS_SFANRPM) {
	    	cmd = edata->private + 1;
	} else
		cmd = edata->private; 

	/* fcu is a macppc only thing so we can safely assume big endian */
	iic_acquire_bus(sc->sc_i2c, 0);
	error = iic_exec(sc->sc_i2c, I2C_OP_READ_WITH_STOP,
	    sc->sc_addr, &cmd, 1, &data, 2, 0);
	iic_release_bus(sc->sc_i2c, 0);

	if (error) {
		edata->state = ENVSYS_SINVALID;
		return;
	}

	edata->state = ENVSYS_SVALID;

	switch (edata->units) {
		case ENVSYS_SFANRPM:
			edata->value_cur = data >> 3;
			break;
		case ENVSYS_SVOLTS_DC:
			/* XXX this reads bogus */
			edata->value_cur = data * 1000;
			break;
		case ENVSYS_INDICATOR:
			/* guesswork for now */
			edata->value_cur = data >> 8;
			break;
		default:
			edata->state = ENVSYS_SINVALID;
	}	
}

static bool
is_cpu(const envsys_data_t *edata)
{
	if (edata->units != ENVSYS_STEMP)
		return false;
	if (strstr(edata->desc, "CPU") != NULL)
		return TRUE;
	return false;
}

static bool
is_case(const envsys_data_t *edata)
{
	if (edata->units != ENVSYS_STEMP)
		return false;
	if ((strstr(edata->desc, "MLB") != NULL) ||
	    (strstr(edata->desc, "BACKSIDE") != NULL) ||
	    (strstr(edata->desc, "U3") != NULL))
		return TRUE;
	return false;
}

static bool
is_drive(const envsys_data_t *edata)
{
	if (edata->units != ENVSYS_STEMP)
		return false;
	if (strstr(edata->desc, "DRIVE") != NULL)
		return TRUE;
	return false;
}

static int
fcu_get_rpm(void *cookie, int which)
{
	struct fcu_softc *sc = cookie;
	fcu_fan_t *f = &sc->sc_fans[which];
	int error;
	uint16_t data = 0;
	uint8_t cmd;

	iic_acquire_bus(sc->sc_i2c, 0);
	cmd = f->reg + 1;
	error = iic_exec(sc->sc_i2c, I2C_OP_READ_WITH_STOP,
	    sc->sc_addr, &cmd, 1, &data, 2, 0);
	iic_release_bus(sc->sc_i2c, 0);
	if (error != 0) return 0;
	data = data >> 3;
	return data;
}

static int
fcu_set_rpm(void *cookie, int which, int speed)
{
	struct fcu_softc *sc = cookie;
	fcu_fan_t *f = &sc->sc_fans[which];
	int error = 0;
	uint8_t cmd;

	if (speed > f->max_rpm) speed = f->max_rpm;
	if (speed < f->base_rpm) speed = f->base_rpm;

	if (f->reg < 0x30) {
		uint16_t data;
		/* simple rpm fan, just poke the register */

		if (f->target == speed) return 0;
		iic_acquire_bus(sc->sc_i2c, 0);
		cmd = f->reg;
		data = (speed << 3);
		error = iic_exec(sc->sc_i2c, I2C_OP_WRITE_WITH_STOP,
		    sc->sc_addr, &cmd, 1, &data, 2, 0);
		iic_release_bus(sc->sc_i2c, 0);
	} else {
		int diff;
		int nduty = f->duty;
		int current_speed;
		/* pwm fan, measure speed, then adjust duty cycle */
		DPRINTF("pwm fan ");
		current_speed = fcu_get_rpm(sc, which);
		diff = current_speed - speed;
		DPRINTF("d %d s %d t %d diff %d ", f->duty, current_speed, speed, diff);
		if (diff > 100) {
			nduty = uimax(20, nduty - 1);
		}
		if (diff < -100) {
			nduty = uimin(0xd0, nduty + 1);
		}
		cmd = f->reg;
		DPRINTF("%s nduty %d", __func__, nduty);
		if (nduty != f->duty) {
			uint8_t arg = nduty;
			iic_acquire_bus(sc->sc_i2c, 0);
			error = iic_exec(sc->sc_i2c, I2C_OP_WRITE_WITH_STOP,
			    sc->sc_addr, &cmd, 1, &arg, 1, 0);
			iic_release_bus(sc->sc_i2c, 0);
			f->duty = nduty;
			sc->sc_pwm = TRUE;

		}
		DPRINTF("ok\n");
	}
	if (error) printf("boo\n");
	f->target = speed;
	return 0;
}

static void
fcu_adjust(void *cookie)
{
	struct fcu_softc *sc = cookie;
	int i;
	uint8_t cmd, data;

	while (!sc->sc_dying) {
		/* poke the FCU so we don't go 747 */
		iic_acquire_bus(sc->sc_i2c, 0);
		cmd = FCU_FAN_ACTIVE;
		iic_exec(sc->sc_i2c, I2C_OP_READ_WITH_STOP,
		    sc->sc_addr, &cmd, 1, &data, 1, 0);
		iic_release_bus(sc->sc_i2c, 0);
		sc->sc_pwm = FALSE;
		for (i = 0; i < FCU_ZONE_COUNT; i++)
			fancontrol_adjust_zone(&sc->sc_zones[i]);
		/*
		 * take a shorter nap if we're in the process of adjusting a
		 * PWM fan, which relies on measuring speed and then changing
		 * its duty cycle until we're reasonable close to the target
		 * speed
		 */
		kpause("fanctrl", true, mstohz(sc->sc_pwm ? 1000 : 2000), NULL);
	}
	kthread_exit(0);
}

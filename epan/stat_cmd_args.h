/* stat_cmd_args.h
 * Declarations of routines to register "-z" command-line argument handlers
 * for stats
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __STAT_CMD_ARGS_H__
#define __STAT_CMD_ARGS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Register a stat ("-z") command line argument.
 *
 * @param cmd The command name without arguments, e.g. "conv,tcp" or "io,stat".
 * MUST be valid when other stat_cmd routines below are called.
 * @param func Callbak to be invoked when the CLI argument is supplied.
 * @param userdata Additional data for the callback.
 */
#if 0
WS_DLL_PUBLIC void register_stat_cmd_arg(const char *cmd,
    void (*func)(const char *arg,void* userdata), void* userdata);
#endif
WS_DLL_PUBLIC gboolean process_stat_cmd_arg(char *optstr);
WS_DLL_PUBLIC void list_stat_cmd_args(void);
WS_DLL_PUBLIC void start_requested_stats(void);

/*
 * Parameters for taps.
 */

#include <epan/params.h>
#include <epan/stat_groups.h>

typedef enum {
	PARAM_UINT,
	PARAM_STRING,
	PARAM_ENUM,
	PARAM_FILTER
} param_type;

typedef struct _tap_param {
	param_type type;
	const char *title;
	const enum_val_t *enum_vals;
} tap_param;

typedef struct _tap_ui {
	register_stat_group_t group;	/* group to which statistic belongs */
	const char *title;		/* title of statistic */
	const char *cli_string;		/* initial part of the "-z" argument for statistic */
	void (* tap_init_cb)(const char *,void*);	/* callback to init function of the tap */
	gint index;			/* initiate this value always with "-1" */
	size_t nparams;			/* number of parameters */
	tap_param *params;		/* pointer to table of parameter info */
} tap_ui;

/*
 * Register the parameters a tap takes.
 */
WS_DLL_PUBLIC void register_tap_ui(tap_ui *ui, void *userdata);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

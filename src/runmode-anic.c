/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

 /**
 * \file
 *
 * \author CounterFlow AI, Inc.
 * \author Randy Caldejon 
 *
 */


#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-erf-dag.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"

#ifdef HAVE_ACCOLADE

#include "util-anic.h"
#include "runmode-anic.h"

static const char *default_mode;

static int AccoladeConfigGetThreadCount(void *conf)
{
    ANIC_CONTEXT *anic_context = (ANIC_CONTEXT *) conf;
    return anic_context->thread_count;
}

static void *ParseAccoladeConfig(const char *mode)
{
    ANIC_CONTEXT *anic_context = SCCalloc(1, sizeof (ANIC_CONTEXT));
    if (unlikely(anic_context == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for Accolade device context.");
        return NULL;
    }
    memset(anic_context, 0, sizeof(ANIC_CONTEXT));

    if (ConfGetInt("anic.interface", &anic_context->index) != 1) {
    	anic_context->index=0;
    }
    const char*steer_mode = NULL;
    if (ConfGet("anic.steer_mode", &steer_mode) != 1) {
    	steer_mode="steerlb";
    }

    if (strncmp (mode,"single",6)==0) {
        /* all ports merged into one thead */
        anic_context->ring_mode = RING16;
        anic_context->thread_count = 1;
fprintf (stderr,"%s:%u ======== %s:steer16\n", __FUNCTION__, __LINE__, mode);
    }
    else {
	if (strncmp(steer_mode,"steer0123",9)==0) {
       	   /* one thread per port */
           anic_context->ring_mode = PORT;
           anic_context->thread_count = 4;
fprintf (stderr,"%s:%u ======== %s:steer0123\n", __FUNCTION__, __LINE__, mode);
        } 
	else if (strncmp(steer_mode,"steer16",7)==0) {
        /* all ports merged into one thead */
        anic_context->ring_mode = RING16;
        anic_context->thread_count = 1;
fprintf (stderr,"%s:%u ======== %s:steer16\n", __FUNCTION__, __LINE__, mode);
        }
	else if (strncmp(steer_mode,"steerlb",7)==0) {
           /* load balance mode */
           anic_context->ring_mode = LOADBALANCE;
           anic_context->thread_count = 8;
fprintf (stderr,"%s:%u ======== %s:steerlb\n", __FUNCTION__, __LINE__, mode);
	}
        else { // undefined
           SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "Invalid Accolade steer mode");
           exit(EXIT_FAILURE);
	}
    }

    anic_context->reset = 1;
    if (ConfGetInt("accolade.nic", &anic_context->index) != 0){
        SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "Invalid Accolade NIC index");
        exit(EXIT_FAILURE);
    }
    
    if (anic_configure(anic_context) < 0) {
        SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "Failed to initialize Accolade NIC");
        exit(EXIT_FAILURE);
    }

    return (void *) anic_context;

}

const char *RunModeAccoladeGetDefaultMode(void)
{
    return default_mode;
}

void RunModeAccoladeRegister(void)
{
#ifdef HAVE_ACCOLADE
    //default_mode = "single";
    default_mode = "workers";

    RunModeRegisterNewRunMode(RUNMODE_ANIC, "autofp",
        "Multi threaded ANIC mode.  Packets from "
        "each flow are assigned to a single detect "
        "thread",
        RunModeAccoladeAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_ANIC, "single",
        "Singled threaded ANIC mode",
        RunModeAccoladeSingle);

    RunModeRegisterNewRunMode(RUNMODE_ANIC, "workers",
        "Workers ANIC mode, each thread does all "
        " tasks from acquisition to logging",
        RunModeAccoladeWorkers);
#endif
    return;
}

int RunModeAccoladeSingle(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    LiveRegisterDevice("anic");

    ret = RunModeSetLiveCaptureSingle(ParseAccoladeConfig,
        AccoladeConfigGetThreadCount,
        "AccoladeReceive",
        "AccoladeDecode",
        thread_name_single,
        "single");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "ANIC single runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsAccoladeSingle initialized");

    SCReturnInt(0);
}

int RunModeAccoladeAutoFp(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    LiveRegisterDevice("anic");

    ret = RunModeSetLiveCaptureAutoFp(ParseAccoladeConfig,
        AccoladeConfigGetThreadCount,
        "AccoladeReceive",
        "AccoladeDecode",
        thread_name_autofp,
        "autofp");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "ANIC autofp runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsAccoladeAutoFp initialized");

    SCReturnInt(0);
}

int RunModeAccoladeWorkers(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    LiveRegisterDevice("anic");

    ret = RunModeSetLiveCaptureWorkers(ParseAccoladeConfig,
        AccoladeConfigGetThreadCount,
        "AccoladeReceive",
        "AccoladeDecode",
        thread_name_workers,
        "workers");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "ANIC workers runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeAccoladeWorkers initialized");

    SCReturnInt(0);
}

#endif

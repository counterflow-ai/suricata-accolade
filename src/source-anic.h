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
 */
#ifndef __SOURCE_ACCOLADE_H__
#define __SOURCE_ACCOLADE_H__

void TmModuleAccoladeReceiveRegister (void);
TmEcode AccoladeThreadDeinit(ThreadVars *tv, void *data);
void TmModuleAccoladeDecodeRegister (void);

#ifdef HAVE_ACCOLADE

#if __FreeBSD__
#include <machine/atomic.h>
#endif

#include "util-anic.h"

typedef struct AccoladePacketVars_
{
    int32_t thread_id;
    uint32_t flow_id;
    uint32_t block_id;
    uint32_t pad;
    ANIC_CONTEXT *anic_context;
} AccoladePacketVars;


#endif /* HAVE_ACCOLADE */
#endif /* __SOURCE_ACCOLADE_H__ */

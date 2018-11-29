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
 *  *
 * Support for Accolade NIC.
 * Requires SDK from Accolade.
 *
 */

#include "suricata-common.h"

#ifdef HAVE_ACCOLADE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "util-anic.h"

// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------
static int anic_map_blocks(ANIC_CONTEXT *ctx)
{
	struct anic_dma_info dma_info;

#ifdef __linux__
#define HUGEPAGE_SIZE (2 * 1024 * 1024)
	// allocate/add 2M hugepage block buffers
	anic_block_set_blocksize(ctx->handle, ANIC_BLOCK_2MB);
	for (uint32_t block = 0; block < ANIC_BLOCK_MAX_BLOCKS; block++)
	{
		const uint32_t shmflags = SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W;
		int shmid = shmget(IPC_PRIVATE, HUGEPAGE_SIZE, shmflags);
		if (shmid == -1)
		{
			SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "shmget() failure error %u %s\n", errno, strerror(errno));
			return -1;
		}
		void *v_p = shmat(shmid, NULL, SHM_RND);
		if (v_p == (void *)-1)
		{
			SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "shmat() failure error %u %s\n", errno, strerror(errno));
			return -1;
		}
		shmctl(shmid, IPC_RMID, NULL);
		memset(v_p, 0xff, 256); // force creation of PTE and verify access
		dma_info.userVirtualAddress = v_p;
		dma_info.length = HUGEPAGE_SIZE;
		dma_info.pageShift = ANIC_2M_PAGE;
		if (anic_map_dma(ctx->handle, &dma_info))
		{
			SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "anic_map_dma() failed\n");
			return -1;
		}
		ctx->blocks[block].virtual_address = (uint8_t *)v_p;
		ctx->blocks[block].dma_address = dma_info.dmaPhysicalAddress;
		anic_block_add(ctx->handle, 0, block, 0, dma_info.dmaPhysicalAddress);
	}

#elif __FreeBSD__
	// allocate and add 2048 block buffers at 2M each
	anic_block_set_blocksize(ctx->handle, ANIC_BLOCK_2MB);
	for (uint32_t block = 0; block < ANIC_BLOCK_MAX_BLOCKS; block++)
	{
		if (anic_acquire_block(ctx->handle, &dma_info))
		{
			SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "anic_acquire_block() failed\n");
			return -1;
		}
		ctx->blocks[block].virtual_address = (uint8_t *)dma_info.userVirtualAddress;
		ctx->blocks[block].dma_address = dma_info.dmaPhysicalAddress;
		anic_block_add(ctx->handle, 0, block, 0, ctx->blocks[block].dma_address);
	}
#else

#error "Accolade does not support this operating system"

#endif
	return 0;
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static int anic_cpu_count(void)
{
	int numCores;
#ifdef __linux__
	numCores = sysconf(_SC_NPROCESSORS_ONLN);
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
	int mib[4];
	size_t len = sizeof(numCores);

	/* set the mib for hw.ncpu */
	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;

	/* get the number of cores from the system */
	sysctl(mib, 2, &numCores, &len, NULL, 0);

	if (numCores < 1)
	{
		numCores = 1;
	}

#else

#error "Unsupported OS platform"

#endif
	return numCores;
}
/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
int anic_configure(ANIC_CONTEXT *ctx)
{
	// Open anic device
	ctx->handle = anic_open("/dev/anic", ctx->index);
	if (anic_error_code(ctx->handle) != ANIC_ERR_NONE)
	{
		SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "ANIC interace %d : %s\n",
				   (int)ctx->index, anic_error_message(ctx->handle));
		anic_close(ctx->handle);
		return -1;
	}

	if (ctx->reset)
	{
		anic_reset_and_restart_pipeline(ctx->handle);
		SCLogInfo("ANIC reset and restart\n");
	}

	char *product_name = anic_get_product_name(ctx->handle);
	anic_get_number_of_ports(ctx->handle, &ctx->port_count);
	SCLogInfo("ANIC %s, ports:%u,  firmware: %u.%u.%u at PCIe geographic address: %02x:%02x:%u\n",
			  product_name, ctx->port_count, ctx->handle->product_info.major_version, ctx->handle->product_info.minor_version,
			  ctx->handle->product_info.sub_version, ctx->handle->product_info.pci_bus,
			  ctx->handle->product_info.pci_slot, ctx->handle->product_info.pci_func);
	if ((ctx->handle->product_info.major_version & 0xf0) != 0x40)
	{
		SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "firmware is not block mode DMA\n");
		anic_close(ctx->handle);
		return -1;
	}
	// print out the FIFO capacity
	//printf("port FIFO capacity  %10u quad-words\n", anic_port_get_queued_limit(ctx->handle));

	switch (ctx->ring_mode)
	{
	case RING16:
		/* all ports merged into one thead */
		ctx->ring_count = 1;
		ctx->ring_mask = 0x0000000000010000L;
		anic_pduproc_steer(ctx->handle, ANIC_STEER16);
		anic_pduproc_dma_pktseq(ctx->handle, 1);
		break;

	case PORT:
		/* one thread per port */
		ctx->ring_count = ctx->port_count;
		ctx->ring_mask |= (1L << ctx->ring_count) - 1;
		anic_pduproc_steer(ctx->handle, ANIC_STEER0123);
		anic_pduproc_dma_pktseq(ctx->handle, 1);
		break;

	case LOADBALANCE:
	default:
		/* load balance mode */
		ctx->ring_count = (anic_cpu_count() / 2);
		ctx->ring_mask = (0x8000000000000000L) | ((1L << ctx->ring_count) - 1);
		ctx->ring_count += 1; // add ring 63
		anic_pduproc_steer(ctx->handle, ANIC_STEERLB);
		anic_pduproc_dma_pktseq(ctx->handle, 1);
		if (anic_setup_rings_largelut(ctx->handle, ctx->ring_count, 0x01, NULL))
		{
			// if large LUT is not supported, fall back to normal LUT
			if (anic_setup_rings(ctx->handle, ctx->ring_count, 0x01, NULL))
			{
				SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "unsupported firmware revision\n");
				return -1;
			}
		}
		break;
	}
	if (ctx->ring_count > ANIC_MAX_NUMBER_OF_RINGS)
	{
		SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "ring count exceeded maximum allowed.\n");
		anic_close(ctx->handle);
		return -1;
	}
	ctx->thread_count = ctx->ring_count;

	// enable packet slicing if necessary
	if (ctx->slice)
	{
		anic_pduproc_slice(ctx->handle, ctx->slice);
	}

	anic_set_ts_disc_mode(ctx->handle, ANIC_TS_DISC_HOST);

	if (anic_map_blocks(ctx) < 0)
	{
		anic_close(ctx->handle);
		return -1;
	}

	// enable rings
	uint32_t thread_id = 0;
	for (uint32_t i = 0; i < ANIC_MAX_NUMBER_OF_RINGS; i++)
	{
		if ((1L << i) & ctx->ring_mask)
		{
			ctx->thread_ring[thread_id++] = i;
			anic_block_set_ring_nodetag(ctx->handle, i, 0);
			anic_block_ena_ring(ctx->handle, i, 1);
		}
	}

	/* 1msec block timeouts */
	anic_block_set_timeouts(ctx->handle, 1000, 1000);

#ifndef ANIC_DISABLE_BYPASS
	/* enable flow shunting "bypass mode" */
	if (ctx->enable_bypass) {
		/*
		 * enable flow shunting with default timeout of 60 seconds
		 */
		if (anic_flow_mode(ctx->handle, ANIC_FLOW_FLAG_ENABLE|
									    ANIC_FLOW_FLAG_TYPE1_DISABLE|
										ANIC_FLOW_FLAG_TYPE2A_DISABLE|
										ANIC_FLOW_FLAG_TYPE2B_DISABLE, ctx->flow_timeout)) {
			SCLogError(SC_ERR_ACCOLADE_INIT_FAILED, "firmware does not support flow shunting\n");
			anic_close(ctx->handle);
			return -1;
		}
	} 
#endif

	/* Clear the RMON and PKIF counters, then enable port */
	for (int port = 0; port < (ctx->port_count); port++)
	{
		anic_get_rx_rmon_counts(ctx->handle, port, 1, NULL);
		anic_port_get_counts(ctx->handle, port, 1, NULL);
		anic_port_ena_disa(ctx->handle, port, 1);
	}

	SCLogInfo("Accolade Network Interface Card (ANIC) is ready");
	return 0;
}

#endif

//
// ------------------------------------------------------------------------------
//

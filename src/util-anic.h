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

#ifdef HAVE_ACCOLADE

#include <time.h>
#include <sys/types.h>
#include <unistd.h>


#ifndef __UTIL_ANIC_H__
#define __UTIL_ANIC_H__

#define BLOCK_MODE_ENA 

#include <anic_api.h>
#include <anic_api_private.h>

#ifndef ANIC_BLOCK_MAX_BLOCKS
#define ANIC_BLOCK_MAX_BLOCKS 2048
#endif

#define ANIC_MAX_PORTS 4
#define ANIC_DEFAULT_BLOCK_SIZE (0x200000)
#define ANIC_MAX_THREADS (ANIC_MAX_NUMBER_OF_RINGS)

// The maximum supported jumbo packet is actually ~9-14K, 16K is rounded up to the next power of 2
#define ANIC_MAX_PACKET_SIZE (16 * 1024)

typedef enum
{
  LOADBALANCE,
  PORT,
  PAIR,
  RING16
} ANIC_MODE;

typedef struct _WORK_QUEUE_
{
  uint32_t head;
  uint32_t tail;
  uint32_t entryA[ANIC_BLOCK_MAX_BLOCKS + 1];
} WORK_QUEUE;

typedef struct _BLOCK_STATUS_
{
  struct anic_blkstatus_s blkStatus;
  volatile uint64_t refcount;
} BLOCK_STATUS;

typedef struct _RING_STATS_
{
  struct
  {
    uint64_t packets;
    uint64_t bytes;
    uint64_t packet_errors;
    uint64_t timestamp_errors;
    uint64_t validation_errors;
    uint64_t pad[3]; // use full cache lines
  } ring[ANIC_MAX_NUMBER_OF_RINGS];
} RING_STATS __attribute__((aligned));

typedef struct _THREAD_STATS_
{
  struct
  {
    uint64_t packets;
    uint64_t bytes;
    uint64_t packet_errors;
    uint64_t timestamp_errors;
    uint64_t validation_errors;
    uint32_t blkf_min;
    uint32_t blkc_max;
    uint64_t pad[2]; // use full cache lines
  } thread[ANIC_MAX_THREADS];
} THREAD_STATS __attribute__((aligned));

typedef struct _BLOCK_REFS_
{
  uint8_t *buf_p;
  uint64_t dma_address;
} BLOCK_REF;

typedef struct _BLOCK_HEADER_
{
  uint32_t block_size;
  uint32_t packet_count;
  uint32_t byte_count;
  uint32_t reserved;
  uint64_t first_timestamp;
  uint64_t last_timestamp;
} BLOCK_HEADER __attribute__((aligned));

typedef struct _ANIC_CONTEXT_
{
  anic_handle_t handle;
  int64_t index;
  int16_t reset;
  int16_t slice;
  uint32_t ring_count;
  int32_t port_count;
  uint32_t thread_count;
  uint64_t ring_mask;
  ANIC_MODE ring_mode;

  RING_STATS ring_stats;
  THREAD_STATS thread_stats;
  BLOCK_REF blocks[ANIC_BLOCK_MAX_BLOCKS];
  BLOCK_STATUS block_status[ANIC_BLOCK_MAX_BLOCKS];
} ANIC_CONTEXT __attribute__((aligned));

int anic_configure(ANIC_CONTEXT *ctx);
uint64_t anic_ring_mask(ANIC_CONTEXT *ctx, uint32_t ring_id);
void anic_create_header(unsigned blocksize, struct anic_blkstatus_s *status_p);
int anic_enable_ports (ANIC_CONTEXT *ctx);

#endif
#endif


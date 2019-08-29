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
#include "suricata.h"
#include "threadvars.h"
#include "util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "source-anic.h"

#include <sys/types.h>

#ifndef HAVE_ACCOLADE


TmEcode NoAccoladeSupportExit(ThreadVars *, const void *, void **);

void TmModuleAccoladeReceiveRegister(void) {
    tmm_modules[TMM_RECEIVEACCOLADE].name = "AccoladeReceive";
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadInit = NoAccoladeSupportExit;
    tmm_modules[TMM_RECEIVEACCOLADE].Func = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleAccoladeDecodeRegister(void) {
    tmm_modules[TMM_DECODEACCOLADE].name = "AccoladeDecode";
    tmm_modules[TMM_DECODEACCOLADE].ThreadInit = NoAccoladeSupportExit;
    tmm_modules[TMM_DECODEACCOLADE].Func = NULL;
    tmm_modules[TMM_DECODEACCOLADE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEACCOLADE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEACCOLADE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEACCOLADE].cap_flags = 0;
    tmm_modules[TMM_DECODEACCOLADE].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoAccoladeSupportExit(ThreadVars *tv, const void *initdata, void **data) {
    SCLogError(SC_ERR_ACCOLADE_NOSUPPORT,
            "Error creating thread %s: you do not have support for Accolade adapter "
            "enabled please recompile with --enable-accolade", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have ACCOLADE support */

#include "util-anic.h"

extern int max_pending_packets;
SC_ATOMIC_DECLARE(uint64_t, g_thread_count);

typedef struct AccoladeThreadVars_ {
    ANIC_CONTEXT *anic_context;
    uint32_t ring_id;
    int32_t thread_id;
    uint32_t flow_id;
    uint32_t pad;
    ThreadVars *tv;
    TmSlot *slot;

    /* counters */
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
} AccoladeThreadVars;

TmEcode AccoladeThreadInit(ThreadVars *, const void *, void **);
void AccoladeThreadExitStats(ThreadVars *, void *);
TmEcode AccoladePacketLoopZC(ThreadVars *tv, void *data, void *slot);

TmEcode AccoladeDecodeThreadInit(ThreadVars *, const void *, void **);
TmEcode AccoladeDecodeThreadDeinit(ThreadVars *tv, void *data);
TmEcode AccoladeDecode(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Register the Accolade  receiver (reader) module.
 */
void TmModuleAccoladeReceiveRegister(void)
{
    tmm_modules[TMM_RECEIVEACCOLADE].name = "AccoladeReceive";
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadInit = AccoladeThreadInit;
    tmm_modules[TMM_RECEIVEACCOLADE].Func = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].PktAcqLoop = AccoladePacketLoopZC;
    tmm_modules[TMM_RECEIVEACCOLADE].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadExitPrintStats = AccoladeThreadExitStats;
    tmm_modules[TMM_RECEIVEACCOLADE].ThreadDeinit = AccoladeThreadDeinit;
    tmm_modules[TMM_RECEIVEACCOLADE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEACCOLADE].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEACCOLADE].flags = TM_FLAG_RECEIVE_TM;

    SC_ATOMIC_INIT(g_thread_count);

}

/**
 * \brief Register the Accolade decoder module.
 */
void TmModuleAccoladeDecodeRegister(void)
{
    tmm_modules[TMM_DECODEACCOLADE].name = "AccoladeDecode";
    tmm_modules[TMM_DECODEACCOLADE].ThreadInit = AccoladeDecodeThreadInit;
    tmm_modules[TMM_DECODEACCOLADE].Func = AccoladeDecode;
    tmm_modules[TMM_DECODEACCOLADE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEACCOLADE].ThreadDeinit = AccoladeDecodeThreadDeinit;
    tmm_modules[TMM_DECODEACCOLADE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEACCOLADE].cap_flags = 0;
    tmm_modules[TMM_DECODEACCOLADE].flags = TM_FLAG_DECODE_TM;
}

/*
 *-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 * Statistics code
 *-----------------------------------------------------------------------------
*/

/**
 * \brief   Initialize the Accolade receiver thread, generate a single
 *          AccoladeThreadVar structure for each thread, this will
 *          contain a NtNetStreamRx_t stream handle which is used when the
 *          thread executes to acquire the packets.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the ACCOLADE
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode AccoladeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    ANIC_CONTEXT *anic_context = (ANIC_CONTEXT *) initdata;
    
    AccoladeThreadVars *atv = SCCalloc(1, sizeof (AccoladeThreadVars));
    if (unlikely(atv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for ACCOLADE  thread vars.");
        exit(EXIT_FAILURE);
    }

    memset(atv, 0, sizeof (AccoladeThreadVars));
    atv->anic_context = anic_context;
    atv->tv = tv;
    atv->thread_id = (SC_ATOMIC_ADD(g_thread_count, 1)-1);
    atv->ring_id = anic_context->thread_ring [atv->thread_id];

    /* basic counters */
    atv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets", atv->tv);
    atv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops", atv->tv);

    struct rx_rmon_counts_s stats;
    if (atv->thread_id < anic_context->port_count){
        /* reset rmon counters */
        anic_get_rx_rmon_counts (anic_context->handle, atv->thread_id, 1,  &stats);
        anic_port_ena_disa(anic_context->handle, atv->thread_id, 1);
    }
    SCLogInfo("Started processing packets for ACCOLADE thread: %u", atv->thread_id);

    *data = (void *) atv;
    SCReturnInt(TM_ECODE_OK);
}

// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------
static void AccoladeReleasePacket(struct Packet_ *p)
{
    if (!PKT_IS_PSEUDOPKT(p)) {
       ANIC_CONTEXT *anic_ctx = p->anic_v.anic_context;
       SC_ATOMIC_SUB(anic_ctx->block_status[p->anic_v.block_id].refcount, 1);
    }
    PacketFreeOrRelease(p);
}

#ifndef ANIC_DISABLE_BYPASS
// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------

static int AccoladeBypassCallback(Packet *p)
{
    /* Only bypass TCP and UDP */
    if (!(PKT_IS_TCP(p) || PKT_IS_UDP(p))) {
        return 0;
    }

    /* Bypassing tunneled packets is currently not supported */
    if (IS_TUNNEL_PKT(p)) {
        return 0;
    }

    ANIC_CONTEXT *anic_ctx = p->anic_v.anic_context;

    anic_flow_filter(anic_ctx->handle, p->anic_v.thread_id, p->anic_v.flow_id, ANIC_FLOW_FLAG_SHUNT_SET);

    SCLogDebug("Bypass set for flow ID = %u", p->anic_v.flow_id);
    return 1;
}

#endif

// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------
static int AccoladeProcessBlock (uint32_t block_id, AccoladeThreadVars *atv)
{
    ANIC_CONTEXT *anic_ctx = atv->anic_context;
    const struct anic_blkstatus_s *blkstatus_p = &anic_ctx->block_status[block_id].blkStatus;

    uint32_t packets = 0;
    uint32_t bytes = 0;
    uint32_t packet_errors = 0;
    uint32_t timestamp_errors = 0;
    uint32_t validation_errors = 0;
    const uint32_t thread_id = atv->thread_id;
    struct anic_descriptor_rx_packet_data *descriptor;
    uint8_t *next_buffer = &blkstatus_p->buf_p[blkstatus_p->firstpkt_offset];

    while (packets < blkstatus_p->pktcnt) {
        descriptor = (struct anic_descriptor_rx_packet_data *)next_buffer;
        // point to the next descriptor
        next_buffer += (descriptor->length + 7) & ~7;

#ifdef DEBUG
        // Packet header checks can be useful for basic application sanity but as noted below,
        // they're not universially applicable so plan accordingl
        assert(descriptor->port < ANIC_MAX_PORTS);
        assert(descriptor->length <= 14348);
        assert(descriptor->origlength <= 14332);
        assert(descriptor->length >= 76);
        assert(descriptor->origlength >= 60);
#endif
 
        Packet *p = NULL;
        uint32_t error = 0;
        uint8_t *packet = NULL;
        uint32_t packet_length = 0;
    
#ifndef ANIC_DISABLE_BYPASS
        if (anic_ctx->enable_bypass) {
            
            /* flow descriptor with packet payload */
            if (descriptor->type == 4) {

                p = PacketGetFromQueueOrAlloc();
                if (unlikely(p == NULL)) {
                    SCReturnInt(TM_ECODE_FAILED);
                }

                struct anic_rx_type4_s *flow_descriptor = (struct anic_rx_type4_s *)descriptor;
                error = flow_descriptor->errorflag;
                packet = (uint8_t *)&flow_descriptor[1];
                packet_length = flow_descriptor->length - sizeof(struct anic_rx_type4_s);

                p->ts.tv_sec = flow_descriptor->timestamp >> 32;
                p->ts.tv_usec = ((flow_descriptor->timestamp & 0xffffffff) * 1000000) >> 32;
                p->BypassPacketsFlow = AccoladeBypassCallback;
                p->anic_v.flow_id = flow_descriptor->flowid;
            }
            /* ignore all other flow descriptor types */
            else continue;
        }
        else
#endif
        if (descriptor->type == ANIC_DESCRIPTOR_RX_PACKET_DATA) {
            
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            
            error = descriptor->anyerr;
            packet = (uint8_t *)&descriptor[1];
            packet_length = descriptor->length - sizeof(struct anic_descriptor_rx_packet_data); 
            p->ts.tv_sec = descriptor->timestamp >> 32;
            p->ts.tv_usec = ((descriptor->timestamp & 0xffffffff) * 1000000) >> 32;
        }
        /* unrecognized descriptor type; unlikely case */
        else {
            SCLogError(SC_ERR_ACCOLADE_NOSUPPORT, "unsupported descriptor type: %i", descriptor->type);
            SCReturnInt(TM_ECODE_FAILED);
        }

        p->datalink = LINKTYPE_ETHERNET;
        p->ReleasePacket = AccoladeReleasePacket;
        p->anic_v.anic_context = anic_ctx;
        p->anic_v.block_id = block_id;
        p->anic_v.thread_id = atv->thread_id;
     
        if (unlikely(PacketSetData(p, (uint8_t *)packet, packet_length))) {
            TmqhOutputPacketpool(atv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(TmThreadsSlotProcessPkt(atv->tv, atv->slot, p) != TM_ECODE_OK)) {
            TmqhOutputPacketpool(atv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        packets++;
        bytes += packet_length;
        if (error) {
            packet_errors++;
        }
    }

    /* update stats counters */
    StatsAddUI64(atv->tv, atv->capture_kernel_packets, (uint64_t)packets);
    StatsSyncCountersIfSignalled(atv->tv);

    /*
     * Keep running stats on a per thread basis
     */
    anic_ctx->thread_stats.thread[thread_id].packets += packets;
    anic_ctx->thread_stats.thread[thread_id].bytes += bytes;
    anic_ctx->thread_stats.thread[thread_id].packet_errors += packet_errors;
    anic_ctx->thread_stats.thread[thread_id].timestamp_errors += timestamp_errors;
    anic_ctx->thread_stats.thread[thread_id].validation_errors += validation_errors;

    return 0;
}


// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------

TmEcode AccoladePacketLoopZC(ThreadVars *tv, void *data, void *slot)
{
    int32_t status;

    AccoladeThreadVars *atv = (AccoladeThreadVars *) data;
    ANIC_CONTEXT *anic_ctx = atv->anic_context;
    const uint32_t thread_id = atv->thread_id;
    const uint64_t ring_id = atv->ring_id;
    struct anic_blkstatus_s blkstatus;
    TmSlot *s = (TmSlot *) slot;

    /* This just keeps the startup output more orderly. */
    usleep(200000 * atv->thread_id);

    SCLogInfo("Accolade Packet Loop Started -  thread: %u ", thread_id);
    //fprintf(stderr,"%s: Accolade Packet Loop Started -  thread: %u\n", __FUNCTION__, thread_id);

    atv->slot = s->slot_next;
    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        memset (&blkstatus, 0, sizeof(blkstatus));
        uint32_t blkcnt = anic_block_get(anic_ctx->handle, thread_id, ring_id, &blkstatus);
        if (blkcnt > anic_ctx->thread_stats.thread[thread_id].blkc_max) {
        	anic_ctx->thread_stats.thread[thread_id].blkc_max = blkcnt;
        }
        if (blkcnt > 0) {
        	uint32_t block_id = blkstatus.blkid;
            /*patch in the virtual address of the block base */
            blkstatus.buf_p = anic_ctx->blocks[block_id].virtual_address;
		    /* housekeeping, update the status block */
        	memcpy (&anic_ctx->block_status[block_id].blkStatus, &blkstatus, sizeof (struct anic_blkstatus_s));
                anic_ctx->block_status[block_id].inuse = 1;
                anic_ctx->block_status[block_id].thread_id = thread_id;
        	SC_ATOMIC_SET(anic_ctx->block_status[block_id].refcount, blkstatus.pktcnt);

            	if ((status=AccoladeProcessBlock(block_id, atv))!=0){
                   SCReturnInt(status);
                }
        }
	    else {
        /*
         * Check status of blocks (packet buffers) in flight, i.e. used by Suricata, 
         * and add back to the ANIC pool. Note, that a buffer is consider done when
         * when the reference count is zero (0)
         */
	        for (int block_id=0; block_id < anic_ctx->max_blocks; block_id++) {
                if ((anic_ctx->block_status[block_id].thread_id == thread_id) &&
                    (anic_ctx->block_status[block_id].inuse) &&
        	        (SC_ATOMIC_GET(anic_ctx->block_status[block_id].refcount)==0)) {
                    anic_ctx->block_status[block_id].inuse=0;
                    anic_ctx->block_status[block_id].thread_id=0;
           	        anic_block_add(anic_ctx->handle, thread_id, block_id, 0, anic_ctx->blocks[block_id].dma_address);
                }
	        }
            /*
             * update buffer counts to monitor queue lengths of free buffers
             */
            uint32_t block_free = anic_block_get_freecount(anic_ctx->handle, 0);
            if (block_free < anic_ctx->thread_stats.thread[thread_id].blkf_min) {
        	    anic_ctx->thread_stats.thread[thread_id].blkf_min = block_free;
            }
       	    usleep(1000);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void AccoladeThreadExitStats(ThreadVars *tv, void *data)
{
    AccoladeThreadVars *atv = (AccoladeThreadVars *) data;
    ANIC_CONTEXT *anic_context = atv->anic_context;
    /*
     * Thread 0 signals to print per port stats
     *  
     */
    if (atv->thread_id==0){
        for (int port=0; port < anic_context->port_count; port++) {
            struct rx_rmon_counts_s stats;
            anic_get_rx_rmon_counts (anic_context->handle, port, 0,  &stats);

            double percent = 0;
            if (stats.rsrc_count > 0) {
                percent = (((double)stats.rsrc_count)
                    / (stats.total_pkts + stats.rsrc_count)) * 100;
            }

            SCLogInfo("port%lu - pkts: %lu; drop: %lu (%5.2f%%); bytes: %lu",
                 (uint64_t) port, stats.total_pkts,
                 stats.rsrc_count, percent, stats.total_bytes);
        }
    }
    /*
     * Print per thread stats
     */
    SCLogInfo("thread%lu - pkts: %lu; bytes: %lu",
                 (uint64_t) atv->thread_id, 
                 anic_context->thread_stats.thread[atv->thread_id].packets,
                 anic_context->thread_stats.thread[atv->thread_id].bytes);

    //anic_context->thread_stats.thread[thread_id].packet_errors;
    //anic_context->thread_stats.thread[thread_id].timestamp_errors;
    //anic_context->thread_stats.thread[thread_id].validation_errors;    
}

/**
 * \brief   Deinitializes the ACCOLADE card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode AccoladeThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    AccoladeThreadVars *atv = (AccoladeThreadVars *) data;
    ANIC_CONTEXT *anic_context = atv->anic_context;
    SCLogDebug("Closing Accolade ring: %d", atv->thread_id);
   
    if (atv->thread_id < anic_context->port_count) {
        anic_port_ena_disa(anic_context->handle, atv->thread_id, 0);
    }
    SCReturnInt(TM_ECODE_OK);
}

/** Decode Accolade */

/**
 * \brief   This function passes off to link type decoders.
 *
 * AccoladeDecode reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode AccoladeDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
        PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *) data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    // update counters
    DecodeUpdatePacketCounters(tv, dtv, p);
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode AccoladeDecodeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *) dtv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode AccoladeDecodeThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);    
}

#endif /* HAVE_ACCOLADE */

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

#ifndef HAVE_ACCOLADE


TmEcode NoAccoladeSupportExit(ThreadVars *, const void *, void **);

void TmModuleAccoladeRegister(void) {
    tmm_modules[TMM_RECEIVEACCOLADE].name = "Accolade";
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
    uint64_t ring_mask;
    uint32_t thread_id;
    uint32_t pad;
    ThreadVars *tv;
    TmSlot *slot;
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
void TmModuleAccoladeRegister(void)
{
    tmm_modules[TMM_RECEIVEACCOLADE].name = "Accolade";
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
    atv->thread_id = SC_ATOMIC_ADD(g_thread_count, 1);
    //atv->thread_id = g_thread_count;
    atv->ring_mask = anic_ring_mask (atv->anic_context, atv->thread_id);

    struct rx_rmon_counts_s stats;
    if (atv->thread_id < anic_context->port_count)
    {
        /* reset rmon counters */
        anic_get_rx_rmon_counts (anic_context->handle, atv->thread_id, 1,  &stats);
        anic_port_ena_disa(anic_context->handle, atv->thread_id, 1);
    }
    SCLogDebug("Started processing packets for ACCOLADE thread: %lu", atv->thread_id);

    *data = (void *) atv;
    SCReturnInt(TM_ECODE_OK);
}

// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------
static void AccoladeReleasePacket(struct Packet_ *p)
{
    PacketFreeOrRelease(p);
    ANIC_CONTEXT *anic_ctx = p->anic_v.anic_context;
    if ((--anic_ctx->block_status[p->anic_v.block_id].refcount)==0)
    {
        anic_block_add(anic_ctx->handle, p->anic_v.thread_id, p->anic_v.block_id, 0, anic_ctx->blocks[p->anic_v.block_id].dma_address);
    }
;
}

// ------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------
static int AccoladeProcessBlock (uint32_t block_id, AccoladeThreadVars *atv)
{
    ANIC_CONTEXT *anic_ctx = atv->anic_context;
    const struct anic_blkstatus_s *blkstatus_p = &anic_ctx->block_status[block_id].blkStatus;
 
    uint32_t thread_id = atv->thread_id;
    uint32_t ring_id = blkstatus_p->ringid;

    uint8_t *buffer = &blkstatus_p->buf_p[blkstatus_p->firstpkt_offset];

    uint8_t *packet;
    uint32_t packets = 0;
    uint32_t bytes = 0;
    uint32_t packet_errors = 0;
    uint32_t timestamp_errors = 0;
    uint32_t validation_errors = 0;
    struct anic_descriptor_rx_packet_data *descriptor;

    anic_ctx->block_status[block_id].refcount = blkstatus_p->pktcnt;
    while (buffer <= &blkstatus_p->buf_p[blkstatus_p->lastpkt_offset]) {
        descriptor = (struct anic_descriptor_rx_packet_data *)buffer;

        // Packet header checks can be useful for basic application sanity but as noted below,
        // they're not universially applicable so plan accordingly.
        assert(descriptor->type == 0);
        assert(descriptor->port < ANIC_MAX_PORTS);
        assert(descriptor->length <= 14348);
        assert(descriptor->origlength <= 14332);
        // these 2 checks will fail in the presence of DMAed runts (40K3) or packets sliced to less than 60
        assert(descriptor->length >= 76);
        assert(descriptor->origlength >= 60);
        // this check will fail on any sliced packet
        assert(descriptor->length - descriptor->origlength == 16);

        // point to the next descriptor
        buffer += (descriptor->length + 7) & ~7;

        packet = (uint8_t *)&descriptor[1];
       
        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        p->ReleasePacket = AccoladeReleasePacket;
        p->anic_v.anic_context = anic_ctx;
        p->anic_v.block_id = block_id;
        p->anic_v.thread_id = atv->thread_id;
        p->datalink = LINKTYPE_ETHERNET;
        p->ts.tv_sec = descriptor->timestamp >> 32;
        p->ts.tv_usec = ((descriptor->timestamp & 0xffffffff) * 1000000) >> 32;

        if (unlikely(PacketSetData(p, (uint8_t *)packet,  descriptor->length - 16))) {
            TmqhOutputPacketpool(atv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(TmThreadsSlotProcessPkt(atv->tv, atv->slot, p) != TM_ECODE_OK)) {
            TmqhOutputPacketpool(atv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        packets++;
        bytes += descriptor->length;
        if (descriptor->anyerr)
            packet_errors++;
    }

    /*
     * Keep running stats on a per thread and per ring basis
     */
    anic_ctx->ring_stats.ring[ring_id].packets += packets;
    anic_ctx->ring_stats.ring[ring_id].bytes += bytes;
    anic_ctx->ring_stats.ring[ring_id].packet_errors += packet_errors;
    anic_ctx->ring_stats.ring[ring_id].timestamp_errors += timestamp_errors;
    anic_ctx->ring_stats.ring[ring_id].validation_errors += validation_errors;
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
    uint32_t thread_id = atv->thread_id;
    uint64_t ring_mask = anic_ring_mask (anic_ctx, thread_id);

    uint32_t block_id;
    uint32_t blkcnt;
    WORK_QUEUE wq;
    uint32_t block_free;
    BLOCK_STATUS *block_status;
    struct anic_blkstatus_s blkstatus;
    unsigned block_size = ANIC_DEFAULT_BLOCK_SIZE; // 2MB

    /* This just keeps the startup output more orderly. */
    usleep(200000 * atv->thread_id);

    SCLogInfo("Accolade Packet Loop Started -  thread: %u ", thread_id);

    TmSlot *s = (TmSlot *) slot;
    atv->slot = s->slot_next;

    memset(&wq, 0, sizeof(wq));

    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        // --------------------------------------------------------------
        // Check work queue for blocks of packets
        // --------------------------------------------------------------
        if (wq.tail != wq.head) {
            block_id = wq.entryA[wq.tail];
            if (wq.tail < ANIC_BLOCK_MAX_BLOCKS)
                wq.tail++;
            else
                wq.tail = 0;

            block_status = &anic_ctx->block_status[block_id];
            if ((status=AccoladeProcessBlock(block_id, atv))!=0){
                SCReturnInt(status);
            }
            //block_status->refcount = 0;
            //anic_block_add(anic_ctx->handle, thread_id, block_id, 0, anic_ctx->blocks[block_id].dma_address);
            continue; // do some more work
        }

        // --------------------------------------------------------------
        // work queue is empty, service anic rings for more blocks
        // --------------------------------------------------------------
        int workQueued = 0;
        for (int ring = 0; ring < ANIC_MAX_NUMBER_OF_RINGS; ring++) {
            if ((1L << ring) & ring_mask){
                for (int i = 0; i < 3; i++) { // pull up to 4 blocks off for each ring
                    blkcnt = anic_block_get(anic_ctx->handle, thread_id, ring, &blkstatus);
                    if (blkcnt > anic_ctx->thread_stats.thread[thread_id].blkc_max) {
                        anic_ctx->thread_stats.thread[thread_id].blkc_max = blkcnt;
                    }
                    if (blkcnt > 0) {
                        workQueued = 1;
                        block_id = blkstatus.blkid;
                        // patch in the virtual address of the block base
                        blkstatus.buf_p = anic_ctx->blocks[block_id].buf_p;
                        // create the block header
                        anic_create_header(block_size, &blkstatus);
                        block_status = &anic_ctx->block_status[block_id];
                        // this unlikely to happen
                        assert (block_status->refcount==0);
                    
                        block_status->blkStatus = blkstatus;
                        wq.entryA[wq.head] = block_id;
                        if (wq.head < ANIC_BLOCK_MAX_BLOCKS) {
                            wq.head++;
                        }
                        else {
                            wq.head = 0;
                        }
                    }
                    else {
                        break; // next ring
                    }
                }
            }
        }

        // --------------------------------------------------------------
        // update buffer counts for status
        // --------------------------------------------------------------
        block_free = anic_block_get_freecount(anic_ctx->handle, 0);
        if (block_free < anic_ctx->thread_stats.thread[thread_id].blkf_min) {
            anic_ctx->thread_stats.thread[thread_id].blkf_min = block_free;
        }
        if (workQueued) {
            continue; // perform work
        }

        // no work, sleep for a bit
        usleep(1000);

        StatsSyncCountersIfSignalled(tv);
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
 * Dump per port statistics
 * 
 */
    if (atv->thread_id < anic_context->port_count)
    {
        struct rx_rmon_counts_s stats;
        anic_get_rx_rmon_counts (anic_context->handle, atv->thread_id, 0,  &stats);
    

        double percent = 0;
        if (stats.rsrc_count > 0)
        {
            percent = (((double)stats.rsrc_count)
                    / (stats.total_pkts + stats.rsrc_count)) * 100;
        }

        SCLogInfo("port%lu - pkts: %lu; drop: %lu (%5.2f%%); bytes: %lu",
                 (uint64_t) atv->thread_id, stats.total_pkts,
                 stats.rsrc_count, percent, stats.total_bytes);
    }
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
   
    if (atv->thread_id < anic_context->port_count)
    {
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

    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                    "Error: datalink type %" PRId32 " not yet supported in module AccoladeDecode",
                    p->datalink);
            break;
    }

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
    SCReturnInt(TM_ECODE_OK);    }

#endif /* HAVE_ACCOLADE */

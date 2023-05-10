/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#include "gro_tcp4.h"

void *
gro_tcp4_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow)
{
	struct gro_tcp4_tbl *tbl;
	size_t size;
	uint32_t entries_num, i;

	entries_num = max_flow_num * max_item_per_flow;
	entries_num = RTE_MIN(entries_num, GRO_TCP4_TBL_MAX_ITEM_NUM);

	if (entries_num == 0)
		return NULL;

	tbl = rte_zmalloc_socket(__func__,
			sizeof(struct gro_tcp4_tbl),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl == NULL)
		return NULL;

	size = sizeof(struct gro_tcp4_item) * entries_num;
	tbl->items = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->items == NULL) {
		rte_free(tbl);
		return NULL;
	}
	tbl->max_item_num = entries_num;

	size = sizeof(struct gro_tcp4_flow) * entries_num;
	tbl->flows = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->flows == NULL) {
		rte_free(tbl->items);
		rte_free(tbl);
		return NULL;
	}
	/* INVALID_ARRAY_INDEX indicates an empty flow */
	for (i = 0; i < entries_num; i++)
		tbl->flows[i].start_index = INVALID_ARRAY_INDEX;
	tbl->max_flow_num = entries_num;

	return tbl;
}

void
gro_tcp4_tbl_destroy(void *tbl)
{
	struct gro_tcp4_tbl *tcp_tbl = tbl;

	if (tcp_tbl) {
		rte_free(tcp_tbl->items);
		rte_free(tcp_tbl->flows);
	}
	rte_free(tcp_tbl);
}

static inline uint32_t
find_an_empty_item(struct gro_tcp4_tbl *tbl)
{
	uint32_t i;
	uint32_t max_item_num = tbl->max_item_num;

	for (i = 0; i < max_item_num; i++)
		if (tbl->items[i].firstseg == NULL)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
find_an_empty_flow(struct gro_tcp4_tbl *tbl)
{
	uint32_t i;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++)
		if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
__insert_new_item(struct gro_tcp4_tbl *tbl,
		struct rte_mbuf *pkt,
		uint64_t start_time,
		uint32_t prev_idx,
		uint32_t sent_seq,
		uint16_t ip_id,
		uint8_t is_atomic,
        const char *func, int line)
{
	uint32_t item_idx;

	item_idx = find_an_empty_item(tbl);
    if (item_idx == INVALID_ARRAY_INDEX) {
        CVM_OPT_LOG("%s:%d ERROR: Item Array Full", func, line);
		return INVALID_ARRAY_INDEX;
    }

	tbl->items[item_idx].firstseg = pkt;
	tbl->items[item_idx].lastseg = rte_pktmbuf_lastseg(pkt);
	tbl->items[item_idx].start_time = start_time;
	tbl->items[item_idx].next_pkt_idx = INVALID_ARRAY_INDEX;
	tbl->items[item_idx].sent_seq = sent_seq;
	tbl->items[item_idx].ip_id = ip_id;
	tbl->items[item_idx].nb_merged = 1;
	tbl->items[item_idx].is_atomic = is_atomic;
	tbl->item_num++;

	/* if the previous packet exists, chain them together. */
	if (prev_idx != INVALID_ARRAY_INDEX) {
		tbl->items[item_idx].next_pkt_idx =
			tbl->items[prev_idx].next_pkt_idx;
		tbl->items[prev_idx].next_pkt_idx = item_idx;
	}

	return item_idx;
}

#define insert_new_item(tbl, pkt, start_time, \
        prev_idx, sent_seq, ip_id, is_atomic) \
        __insert_new_item(tbl, pkt, start_time,\
                prev_idx, sent_seq, ip_id, \
                is_atomic, __func__, __LINE__)

static inline uint32_t
delete_item(struct gro_tcp4_tbl *tbl, uint32_t item_idx,
		uint32_t prev_item_idx)
{
	uint32_t next_idx = tbl->items[item_idx].next_pkt_idx;

	/* NULL indicates an empty item */
	tbl->items[item_idx].firstseg = NULL;
	tbl->item_num--;
	if (prev_item_idx != INVALID_ARRAY_INDEX)
		tbl->items[prev_item_idx].next_pkt_idx = next_idx;

	return next_idx;
}

static inline uint32_t
insert_new_flow(struct gro_tcp4_tbl *tbl,
		struct tcp4_flow_key *src,
		uint32_t item_idx)
{
	struct tcp4_flow_key *dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
    if (unlikely(flow_idx == INVALID_ARRAY_INDEX))
		return INVALID_ARRAY_INDEX;

	dst = &(tbl->flows[flow_idx].key);

	rte_ether_addr_copy(&(src->eth_saddr), &(dst->eth_saddr));
	rte_ether_addr_copy(&(src->eth_daddr), &(dst->eth_daddr));
	dst->ip_src_addr = src->ip_src_addr;
	dst->ip_dst_addr = src->ip_dst_addr;
	dst->recv_ack = src->recv_ack;
	dst->src_port = src->src_port;
	dst->dst_port = src->dst_port;

	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flows[flow_idx].flush = 0;
	tbl->flow_num++;

	return flow_idx;
}


static inline uint32_t
__insert_gro_flow(struct gro_tcp4_tbl *tbl,
		struct tcp4_flow_key *key_src,
        struct net_hdr_info *info_src,
		uint32_t item_idx,
        uint64_t start_time,
        const char *func,
        int line)
{

	struct tcp4_flow_key *key_dst;
	struct net_hdr_info *info_dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
    if (unlikely(flow_idx == INVALID_ARRAY_INDEX)) {
        CVM_OPT_LOG("%s:%s:%d ERROR", __func__, func, line);
		return INVALID_ARRAY_INDEX;
    }

	key_dst = &(tbl->flows[flow_idx].key);
	info_dst = &(tbl->flows[flow_idx].info);

    /**
     * copy tcp_key
     */
	rte_ether_addr_copy(&(key_src->eth_saddr), &(key_dst->eth_saddr));
	rte_ether_addr_copy(&(key_src->eth_daddr), &(key_dst->eth_daddr));
	key_dst->ip_src_addr = key_src->ip_src_addr;
	key_dst->ip_dst_addr = key_src->ip_dst_addr;
	key_dst->recv_ack = key_src->recv_ack;
	key_dst->src_port = key_src->src_port;
	key_dst->dst_port = key_src->dst_port;

    /**
     * copy net_hdr_info
     */
    info_dst->eth_hdr = info_src->eth_hdr;
    info_dst->ipv4_hdr = info_src->ipv4_hdr;
    info_dst->tcp_hdr = info_src->tcp_hdr;
    info_dst->tcp_hdr_len = info_src->tcp_hdr_len;
    info_dst->sent_seq = info_src->sent_seq;
    info_dst->tcp_dl = info_src->tcp_dl;
    info_dst->ip_id = info_src->ip_id;
    info_dst->hdr_len = info_src->hdr_len;
    info_dst->frag_off = info_src->frag_off;
    info_dst->is_atomic = info_src->is_atomic;


    tbl->flows[flow_idx].start_time = start_time;
	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flows[flow_idx].flush = 0;
	tbl->flow_num++;

	return flow_idx;
}

#define insert_gro_flow(tbl, key, info, item_idx, start_time) \
    __insert_gro_flow(tbl, key, info, item_idx, start_time, __func__, __LINE__)

/*
 * update the packet length for the flushed packet.
 */
static inline void
update_header(struct gro_tcp4_item *item)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *pkt = item->firstseg;

	ipv4_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			pkt->l2_len);
	ipv4_hdr->total_length = rte_cpu_to_be_16(pkt->pkt_len -
			pkt->l2_len);
}

int32_t
gro_tcp4_reassemble(struct rte_mbuf *pkt,
		struct gro_tcp4_tbl *tbl,
		uint64_t start_time)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	uint32_t sent_seq;
	int32_t tcp_dl;
	uint16_t ip_id, hdr_len, frag_off;
	uint8_t is_atomic;

	struct tcp4_flow_key key;
	uint32_t cur_idx, prev_idx, item_idx;
	uint32_t i, max_flow_num, remaining_flow_num;
	int cmp;
	uint8_t find;

	/*
	 * Don't process the packet whose TCP header length is greater
	 * than 60 bytes or less than 20 bytes.
	 */
#ifdef CVM_OPT
	if (unlikely(INVALID_TCP_HDRLEN(pkt->l4_len))) {
        CVM_OPT_LOG("ERROR. GRO failed: pkt->l4_len %u\n", pkt->l4_len);
		return -1;
    }
#else
	if (unlikely(INVALID_TCP_HDRLEN(pkt->l4_len)))
		return -1;
#endif

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + pkt->l2_len);
	tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + pkt->l3_len);
	hdr_len = pkt->l2_len + pkt->l3_len + pkt->l4_len;
	sent_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

	/*
	 * Don't process the packet which has FIN, SYN, RST, PSH, URG, ECE
	 * or CWR set.
	 */
#ifdef CVM_OPT
#if 1
    if (tcp_hdr->tcp_flags & (~(RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG))) {
        CVM_OPT_LOG("ERROR. GRO failed: seq: %u tcp_hdr->tcp_flags %u\n",
               sent_seq, tcp_hdr->tcp_flags);
		return -1;
    }
#endif
#else
	if (tcp_hdr->tcp_flags != RTE_TCP_ACK_FLAG)
		return -1;
#endif
	/*
	 * Don't process the packet whose payload length is less than or
	 * equal to 0.
	 */
	tcp_dl = pkt->pkt_len - hdr_len;
#ifdef CVM_OPT
	if (tcp_dl <= 0) {
        CVM_OPT_LOG("ERROR. GRO failed: sent_seq: %u tcp_dl %d\n", sent_seq, tcp_dl);
		return -1;
    }
#else
	if (tcp_dl <= 0)
		return -1;
#endif

	/*
	 * Save IPv4 ID for the packet whose DF bit is 0. For the packet
	 * whose DF bit is 1, IPv4 ID is ignored.
	 */
	frag_off = rte_be_to_cpu_16(ipv4_hdr->fragment_offset);
	is_atomic = (frag_off & RTE_IPV4_HDR_DF_FLAG) == RTE_IPV4_HDR_DF_FLAG;
	ip_id = is_atomic ? 0 : rte_be_to_cpu_16(ipv4_hdr->packet_id);

	rte_ether_addr_copy(&(eth_hdr->src_addr), &(key.eth_saddr));
	rte_ether_addr_copy(&(eth_hdr->dst_addr), &(key.eth_daddr));
	key.ip_src_addr = ipv4_hdr->src_addr;
	key.ip_dst_addr = ipv4_hdr->dst_addr;
	key.src_port = tcp_hdr->src_port;
	key.dst_port = tcp_hdr->dst_port;
	key.recv_ack = tcp_hdr->recv_ack;

	/* Search for a matched flow. */
	max_flow_num = tbl->max_flow_num;
	remaining_flow_num = tbl->flow_num;
	int old_remaining_flow_num = tbl->flow_num;
	find = 0;
	for (i = 0; i < max_flow_num && remaining_flow_num; i++) {
		if (tbl->flows[i].start_index != INVALID_ARRAY_INDEX) {
			if (is_same_tcp4_flow(tbl->flows[i].key, key)) {
				find = 1;
				break;
			}
			remaining_flow_num--;
		}
	}

	/*
	 * Fail to find a matched flow. Insert a new flow and store the
	 * packet into the flow.
	 */
	if (find == 0) {
		item_idx = insert_new_item(tbl, pkt, start_time,
				INVALID_ARRAY_INDEX, sent_seq, ip_id,
				is_atomic);
        if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		if (insert_new_flow(tbl, &key, item_idx) ==
				INVALID_ARRAY_INDEX) {
            CVM_OPT_LOG("ERROR: Flow Array Full");
			/*
			 * Fail to insert a new flow, so delete the
			 * stored packet.
			 */
			delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
			return -1;
		}
        CVM_OPT_LOG("Fail to find matched flow seq: %u remaining_flow_num: %d", 
                sent_seq, old_remaining_flow_num);
		return 0;
	}

	/*
	 * Check all packets in the flow and try to find a neighbor for
	 * the input packet.
	 */
	uint32_t iter = tbl->flows[i].start_index;
	cur_idx = tbl->flows[i].start_index;
	prev_idx = cur_idx;

	do {
        // struct gro_tcp4_item *item = &(tbl->items[iter]);
        // CVM_OPT_LOG("seq: %u len: %lu", 
        //         !mybase ? item->sent_seq : ((item->sent_seq - mybase) / 1448), 
        //         item->firstseg->l4_len - sizeof(struct rte_tcp_hdr));
		iter = tbl->items[iter].next_pkt_idx;
	} while (iter != INVALID_ARRAY_INDEX);

	do {
		cmp = check_seq_option(&(tbl->items[cur_idx]), tcp_hdr,
				sent_seq, ip_id, pkt->l4_len, tcp_dl, 0,
				is_atomic);
		if (cmp) {
			if (merge_two_tcp4_packets(&(tbl->items[cur_idx]),
                        pkt, cmp, sent_seq, ip_id, 0)) {
                CVM_OPT_LOG("MERGE seq: %u cur seq: %u", tbl->items[cur_idx].sent_seq, sent_seq);
				return 1;
            }
			/*
			 * Fail to merge the two packets, as the packet
			 * length is greater than the max value. Store
			 * the packet into the flow.
			 */
			if (insert_new_item(tbl, pkt, start_time, prev_idx,
						sent_seq, ip_id, is_atomic) ==
                    INVALID_ARRAY_INDEX)
                return -1;
            CVM_OPT_LOG("seq: %u len: %u find neighbor but failed to merge. "
                        "insert into flow: %d", sent_seq, tcp_dl, i);
			return 0;
		}
		prev_idx = cur_idx;
		cur_idx = tbl->items[cur_idx].next_pkt_idx;
	} while (cur_idx != INVALID_ARRAY_INDEX);


    CVM_OPT_LOG("seq: %u len: %u find flow but no neighbor. insert into flow: %d", 
            sent_seq, tcp_dl, i);

	/* Fail to find a neighbor, so store the packet into the flow. */
	if (insert_new_item(tbl, pkt, start_time, prev_idx, sent_seq,
                ip_id, is_atomic) == INVALID_ARRAY_INDEX)
		return -1;

	return 0;
}

static void __get_net_hdr(
        struct rte_mbuf *pkt,
        struct net_hdr_info *info,
        const char *func,
        int32_t line)
{
    if (!pkt->l2_len || !pkt->l3_len || !pkt->l4_len) {
        CVM_OPT_LOG("%s:%d ERROR: l2_len: %u l3_len: %u l4_len: %u", 
                func, line, pkt->l2_len, pkt->l3_len, pkt->l4_len);
    }
	info->eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	info->ipv4_hdr = (struct rte_ipv4_hdr *)((char *)info->eth_hdr + pkt->l2_len);
	info->tcp_hdr = (struct rte_tcp_hdr *)((char *)info->ipv4_hdr + pkt->l3_len);
    info->tcp_hdr_len = pkt->l4_len;
	info->hdr_len = pkt->l2_len + pkt->l3_len + pkt->l4_len;
	info->sent_seq = rte_be_to_cpu_32(info->tcp_hdr->sent_seq);
	info->tcp_dl = pkt->pkt_len - info->hdr_len;
	info->frag_off = rte_be_to_cpu_16(info->ipv4_hdr->fragment_offset);
	info->is_atomic = (info->frag_off & RTE_IPV4_HDR_DF_FLAG) == RTE_IPV4_HDR_DF_FLAG;
	info->ip_id = info->is_atomic ? 0 : rte_be_to_cpu_16(info->ipv4_hdr->packet_id);
}

#define get_net_hdr(pkt, info) \
    __get_net_hdr(pkt, info, __func__, __LINE__)

static void fill_key(struct net_hdr_info *info, struct tcp4_flow_key *key)
{
	rte_ether_addr_copy(&(info->eth_hdr->src_addr), &(key->eth_saddr));
	rte_ether_addr_copy(&(info->eth_hdr->dst_addr), &(key->eth_daddr));
	key->ip_src_addr = info->ipv4_hdr->src_addr;
	key->ip_dst_addr = info->ipv4_hdr->dst_addr;
	key->src_port = info->tcp_hdr->src_port;
	key->dst_port = info->tcp_hdr->dst_port;
	key->recv_ack = info->tcp_hdr->recv_ack;
}

static int32_t __attribute__((noinline)) tcp_gro_receive(
		struct gro_tcp4_tbl *tbl,
        struct rte_mbuf *pkt,
        uint32_t *cur_flush,
        uint32_t *cur_same_flow,
        struct net_hdr_info *cur_info,
        struct tcp4_flow_key *cur_key)
{
    int32_t flush = 1, flow_idx = -1;
	uint32_t max_flow_num = tbl->max_flow_num;
	uint32_t remaining_flow_num = tbl->flow_num;
    uint32_t i, mss = 1;
    uint16_t cmp_len;
    struct gro_tcp4_flow *p;
    struct net_hdr_info *peer_info;
    uint32_t gro_len = cur_info->tcp_dl + pkt->l4_len;
    bool is_neighbor;


	for (i = 0; i < max_flow_num && remaining_flow_num; i ++ ) {
        if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
            continue;
        remaining_flow_num -- ;

        p = &(tbl->flows[i]);
        peer_info = (&p->info);

        if (!p->same_flow) continue;

        if (!is_same_tcp4_flow(p->key, *cur_key)) {
            // CVM_OPT_LOG(" [9] tcp_same_flow failed peer_seq: %u cur_seq: %u", 
            //         peer_info->sent_seq, cur_info->sent_seq); 
            p->same_flow = 0;
            continue;
        }
        cmp_len = RTE_MAX(cur_info->tcp_hdr_len, peer_info->tcp_hdr_len) -
            sizeof(struct rte_tcp_hdr);
        
        goto found;
	}
    /* CVM_OPT_LOG(" [3] none same flow seq: %u", cur_info->sent_seq); */
    p = NULL;
    goto out_check_final;

found:
    /* FIXME: Linux use tcp_word_hdr->words here. */
    flush = p->flush;
    flush |= (int)(cur_info->tcp_hdr->tcp_flags & RTE_TCP_CWR_FLAG);
    /* FIXME: Linux use tcp_flag_word here. */
	flush |= (int)((cur_info->tcp_hdr->tcp_flags ^ peer_info->tcp_hdr->tcp_flags) & 
            ~(RTE_TCP_CWR_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_PSH_FLAG));
    flush |= (int)(cur_info->tcp_hdr->recv_ack ^ cur_info->tcp_hdr->recv_ack);
    /**
     * Compare TCP Option Fields
     */
    if (cur_info->tcp_hdr_len < 20 || peer_info->tcp_hdr_len < 20) {
        CVM_OPT_LOG("ERROR. cur_tcp_hdr_len: %d peer_tcp_hdr_len: %d",
                cur_info->tcp_hdr_len, peer_info->tcp_hdr_len); 
    }
	int option_cmp = (int)((cur_info->tcp_hdr_len != peer_info->tcp_hdr_len) || 
             ((cmp_len > 0) && (memcmp(cur_info->tcp_hdr + 1,
                     peer_info->tcp_hdr+ 1, cmp_len) != 0)));
    flush |= option_cmp;
    if (option_cmp) {
        // CVM_OPT_LOG(" [13] OPTION MISMATCH. seq: %u tcp_hdr_len: %u peer_seq: %u peer_tcp_hdr_len: %u", 
        //         cur_info->sent_seq, cur_info->tcp_hdr_len,
        //         peer_info->sent_seq, peer_info->tcp_hdr_len);
    }


    /* FIXME: wtf is flush ID ?? */
    // flush |= NAPI_GRO_CB(p)->flush_id;
    //      if (NAPI_GRO_CB(p)->flush_id != 1 ||
    //     NAPI_GRO_CB(p)->count != 1 ||
    //     !NAPI_GRO_CB(p)->is_atomic)
    //      flush |= NAPI_GRO_CB(p)->flush_id;
    //  else
    //      NAPI_GRO_CB(p)->is_atomic = false;

    /* TODO: substitute 1398 with skb_shinfo(p)->gso_size */
    mss = 1398;

    /* FIXME: ignore this temporarily */
    /* flush |= (gro_len - 1) >= mss; */
	is_neighbor = ((cur_info->sent_seq == (peer_info->sent_seq + peer_info->tcp_dl)) && 
              (cur_info->is_atomic || (cur_info->ip_id == peer_info->ip_id + 1)));
    flush |= !is_neighbor;
    if (!is_neighbor) {
        // CVM_OPT_LOG(" [12] cur_seq: %u peer_seq: %u peer_dl: %u cur_atomic: %u cur_ipid: %u peer_ipid: %u", 
        //         cur_info->sent_seq, peer_info->sent_seq, peer_info->tcp_dl, cur_info->is_atomic, cur_info->ip_id, peer_info->ip_id);
    }
    /* CVM_OPT_LOG(" [3] has same flow. seq: %u flush: %u gro_len: %u mss: %u is_neighbor: %s", */ 
    /*             cur_info->sent_seq, flush, gro_len, mss, is_neighbor ? "true" : "false"); */

    if (!flush) {
		if (merge_two_tcp4_packets(&(tbl->items[p->start_index]),
                    pkt, 1, cur_info->sent_seq, cur_info->ip_id, 0)) {
            // CVM_OPT_LOG(" [15] MERGE seq: %u --> seq: %u peer_tcp_dl: %u cur_tcp_dl: %u", 
            //         peer_info->sent_seq, cur_info->sent_seq,
            //         peer_info->tcp_dl, cur_info->tcp_dl);
            peer_info->tcp_dl += cur_info->tcp_dl;
            *cur_same_flow = 1;
            mss = 1;
            goto out_check_final;
        } else {
            CVM_OPT_LOG("ERROR.");
        }
    } else {
        mss = 1;
        goto out_check_final;
    }


out_check_final:
    flush = gro_len < mss;
    flush |= (int)(cur_info->tcp_hdr->tcp_flags & 
             (RTE_TCP_URG_FLAG | RTE_TCP_PSH_FLAG |
              RTE_TCP_RST_FLAG | RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

    if (p && (!*cur_same_flow || flush))
        flow_idx = i;

    *cur_flush |= (flush != 0);
    // CVM_OPT_LOG(" [4] out_check_final. cur_flush: %u flush: %u gro_len: %u mss: %u seq: %u "
    //         "URG: %s PSH: %s RST: %s SYN: %s FIN: %s",
    //         *cur_flush, flush, gro_len, mss, cur_info->sent_seq,
    //         cur_info->tcp_hdr->tcp_flags & RTE_TCP_URG_FLAG ? "true" : "false",
    //         cur_info->tcp_hdr->tcp_flags & RTE_TCP_PSH_FLAG ? "true" : "false",
    //         cur_info->tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG ? "true" : "false",
    //         cur_info->tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG ? "true" : "false",
    //         cur_info->tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG ? "true" : "false");


    return flow_idx;
}

static int32_t __attribute__((noinline)) inet_gro_receive(
		struct gro_tcp4_tbl *tbl,
        struct rte_mbuf *pkt,
        uint32_t *cur_flush,
        uint32_t *cur_same_flow,
        struct net_hdr_info *cur_info,
        struct tcp4_flow_key *cur_key)
{
    int flush = 1;
	uint32_t max_flow_num = tbl->max_flow_num;
	uint32_t remaining_flow_num = tbl->flow_num;
    /**
     * FIXME: is this right ?
     */
    uint32_t gro_len = cur_info->tcp_dl + pkt->l3_len + pkt->l4_len;
    struct gro_tcp4_flow *p;
    struct net_hdr_info *peer_info;

    flush = (uint16_t)((ntohl(*(uint32_t *)cur_info->ipv4_hdr) ^ gro_len) |
                        (cur_info->ip_id & ~IP_DF));

	for (uint32_t i = 0; i < max_flow_num && remaining_flow_num; i ++ ) {

        if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
            continue;
        remaining_flow_num -- ;

        p = &(tbl->flows[i]);
        peer_info = (&p->info);

        if (!p->same_flow)
            continue;

        // FIXME: redundant check.
		if (!is_same_inet_flow(p->key, *cur_key)) {
            // CVM_OPT_LOG(" [8] inet_same_flow failed peer_seq: %u cur_seq: %u", 
            //         peer_info->sent_seq, cur_info->sent_seq); 
            p->same_flow = 0;
            continue;
        } 
        p->flush |= (cur_info->ipv4_hdr->time_to_live ^
                        peer_info->ipv4_hdr->time_to_live) |
                    (cur_info->ipv4_hdr->type_of_service ^
                        peer_info->ipv4_hdr->type_of_service) |
                    ((cur_info->ipv4_hdr->fragment_offset ^
                        peer_info->ipv4_hdr->fragment_offset) & htons(IP_DF));
        p->flush |= flush;
	}

    *cur_flush |= flush;

    /* CVM_OPT_LOG(" [2] flush: %u cur_flush: %u seq: %u", */ 
    /*         flush, *cur_flush, cur_info->sent_seq); */

    return tcp_gro_receive(tbl, pkt, cur_flush, cur_same_flow, cur_info, cur_key);

}

static void gro_list_prepare(
        struct gro_tcp4_tbl *tbl, 
        struct tcp4_flow_key *cur_key,
        struct net_hdr_info *cur_info)
{
	uint32_t max_flow_num = tbl->max_flow_num;
	uint32_t remaining_flow_num = tbl->flow_num;
    
	for (uint32_t i = 0; i < max_flow_num && remaining_flow_num; i ++ ) {
        if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX) 
            continue;
        remaining_flow_num -- ;

        tbl->flows[i].flush = 0;
        tbl->flows[i].same_flow = is_same_mac_flow(*cur_key, tbl->flows[i].key);
        if (!tbl->flows[i].same_flow) {
            const uint16_t *cur_dmac = (const uint16_t *)(&cur_key->eth_daddr);
            const uint16_t *peer_dmac = (const uint16_t *)(&tbl->flows[i].key.eth_daddr);
            // CVM_OPT_LOG(" [7] mac_same_flow failed cur_seq: %u cur_dmac: %u-%u-%u "
            //         "peer_seq: %u peer_dmac: %u-%u-%u peer_idx: %d", 
            //         cur_info->sent_seq, cur_dmac[0], cur_dmac[1], cur_dmac[2],
            //         tbl->flows[i].info.sent_seq, peer_dmac[0], peer_dmac[1], peer_dmac[2], i); 
        }
    }
}


int32_t
dev_gro_receive(struct rte_mbuf *pkt, struct rte_mbuf **out,
		struct gro_tcp4_tbl *tbl,
		uint64_t start_time,
        uint32_t start_idx)
{
    struct net_hdr_info cur_info;
	struct tcp4_flow_key cur_key;
    uint32_t item_idx, cur_same_flow = 0, cur_flush = 0;
    int32_t flow_idx;

    get_net_hdr(pkt, &cur_info);

	if (cur_info.tcp_dl <= 0) {
        /* CVM_OPT_LOG("ERROR. GRO failed: sent_seq: %u tcp_dl %d pkt_len: %u\n", */ 
        /*         cur_info.sent_seq, cur_info.tcp_dl, pkt->pkt_len); */
        out[start_idx ++ ] = pkt;
		return start_idx;
    }

    fill_key(&cur_info, &cur_key);

    /* CVM_OPT_LOG(" [1] GRO START seq: %u ", cur_info.sent_seq); */

    gro_list_prepare(tbl, &cur_key, &cur_info);


    flow_idx = inet_gro_receive(tbl, pkt, &cur_flush,
        &cur_same_flow, &cur_info, &cur_key);


    /* CVM_OPT_LOG(" [5] GRO END seq: %u flow_idx: %d cur_same_flow: %u cur_flush: %u", */ 
    /*         cur_info.sent_seq, flow_idx, cur_same_flow, cur_flush); */

    if (flow_idx != -1) {
        start_idx = gro_flush_flow(tbl, flow_idx, start_idx, out);
    }

    if (cur_same_flow)
        return start_idx;

    if (cur_flush) {
        out[start_idx ++ ] = pkt;
        return start_idx;
    }

    if (unlikely(tbl->flow_num >= 8)) {
        start_idx = gro_flush_oldest(tbl, start_idx, out);
    }

    /**
     * insert current pkt as a new flow
     */

	item_idx = insert_new_item(tbl, pkt, start_time,
			INVALID_ARRAY_INDEX, cur_info.sent_seq, cur_info.ip_id,
			cur_info.is_atomic);
    if (item_idx == INVALID_ARRAY_INDEX) {
        out[start_idx ++ ] = pkt;
        return start_idx;
    }
	if (insert_gro_flow(tbl, &cur_key, &cur_info, item_idx, start_time) ==
			INVALID_ARRAY_INDEX) {
		delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
        out[start_idx ++ ] = pkt;
        return start_idx;
	}
    /* CVM_OPT_LOG(" [6] insert flow successfully"); */
	return start_idx;
}

uint16_t
gro_tcp4_tbl_timeout_flush(struct gro_tcp4_tbl *tbl,
		uint64_t flush_timestamp,
		struct rte_mbuf **out,
		uint16_t nb_out)
{
	uint16_t k = 0;
	uint32_t i, j;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++) {
		if (unlikely(tbl->flow_num == 0))
			return k;

		j = tbl->flows[i].start_index;
		while (j != INVALID_ARRAY_INDEX) {
			if (tbl->items[j].start_time <= flush_timestamp) {
				out[k++] = tbl->items[j].firstseg;
				if (tbl->items[j].nb_merged > 1)
					update_header(&(tbl->items[j]));
				/*
				 * Delete the packet and get the next
				 * packet in the flow.
				 */
				j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
				tbl->flows[i].start_index = j;
				if (j == INVALID_ARRAY_INDEX)
					tbl->flow_num--;

				if (unlikely(k == nb_out))
					return k;
			} else
				/*
				 * The left packets in this flow won't be
				 * timeout. Go to check other flows.
				 */
				break;
		}
	}
	return k;
}

uint16_t
gro_flush_flow(
        struct gro_tcp4_tbl *tbl,
        uint32_t flow_idx,
        uint32_t start_idx,
		struct rte_mbuf **out)
{
    uint16_t k = start_idx;
	uint32_t j = tbl->flows[flow_idx].start_index;

	while (j != INVALID_ARRAY_INDEX) {
		out[k++] = tbl->items[j].firstseg;
		if (tbl->items[j].nb_merged > 1)
			update_header(&(tbl->items[j]));
		/*
		 * Delete the packet and get the next
		 * packet in the flow.
		 */
		j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
		tbl->flows[flow_idx].start_index = j;
		if (j == INVALID_ARRAY_INDEX)
			tbl->flow_num--;
    }
    return k;
}

uint16_t
gro_flush_oldest(
        struct gro_tcp4_tbl *tbl,
        uint32_t start_idx,
		struct rte_mbuf **out)
{
	uint32_t max_flow_num = tbl->max_flow_num;
	uint32_t remaining_flow_num = tbl->flow_num;
    int32_t flow_idx = -1;
    uint64_t old = INT64_MAX;

	for (uint32_t i = 0; i < max_flow_num && remaining_flow_num; i ++ ) {
        if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
            continue;
        remaining_flow_num -- ;
        if (tbl->flows[i].start_time < old) {
            old = tbl->flows[i].start_time;
            flow_idx = i;
        }
    }

    if (likely(flow_idx != -1))
        return gro_flush_flow(tbl, flow_idx, start_idx, out);
    return start_idx;
}

uint32_t
gro_tcp4_tbl_pkt_count(void *tbl)
{
	struct gro_tcp4_tbl *gro_tbl = tbl;

	if (gro_tbl)
		return gro_tbl->item_num;

	return 0;
}

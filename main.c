#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/netlink.h>
#include <linux/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <linux/ip.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include "params.h"

struct dwrr_rate_cfg
{
	u64	rate_bps;
	u32	mult;
	u32	shift;
};

struct dwrr_class
{
	u8		id;
	u8		prio;
	u32		len_bytes;
	struct Qdisc	*qdisc;

	u32		deficit;
	s64		start_time;
	s64		last_pkt_time;
	u32		quantum;
	struct list_head	alist;

	u32		count;
	u32		lastcount;
	bool		marking;
	u32 totpkts;
	u32 droppkts;
	u32 evictpkts;
	u32 mismatchpkts;
	u32 perq_bytes;
	u16		rec_inv_sqrt;
	codel_time_t	first_above_time;
	codel_time_t	mark_next;
	codel_time_t	ldelay;
};

struct dwrr_sched_data
{
	struct dwrr_class	queues[dwrr_max_queues];
	struct dwrr_rate_cfg	rate;
	struct qdisc_watchdog	watchdog;
	struct list_head	active[dwrr_max_prio];
	u32 num_active_queues; // dropx
	u32 sum_perq;
	s64	tokens;
	s64	time_ns;
	u32	sum_len_bytes;
	u32 cedm_avgs;
	s64 cedm_prev_t;
	u32 cedm_prev_qlen;
	u32	prio_len_bytes[dwrr_max_prio];
	s64	round_time[dwrr_max_prio];
	s64	last_idle_time[dwrr_max_prio];
};

static inline struct sk_buff *qdisc_peek_tail(struct Qdisc *sch)
{
	return skb_peek_tail(&sch->q);
}

static inline void print_dwrr_sched_data(struct Qdisc *sch)
{
}

/* nanosecond to codel time (1 << dwrr_codel_shift ns) */
static inline codel_time_t ns_to_codel_time(s64 ns)
{
	return ns >> dwrr_codel_shift;
}

/* Exponential Weighted Moving Average (EWMA) for s64 */
static inline s64 s64_ewma(s64 smooth, s64 sample, int weight, int shift)
{
	s64 val = smooth * weight;
	val += sample * ((1 << shift) - weight);
	return val >> shift;
}

/* Use EWMA to update round time */
static inline s64 ewma_round(s64 smooth, s64 sample)
{
	return s64_ewma(smooth, sample, dwrr_round_alpha, dwrr_round_shift);
}

/* Reset round time after a long period of idle time */
static void reset_round(struct dwrr_sched_data *q, int prio)
{
	int i;
	s64 interval, iter = 0;

	if (likely(q->prio_len_bytes[prio] == 0 && dwrr_idle_interval_ns > 0))
	{
		interval = ktime_get_ns() - q->last_idle_time[prio];
		iter = div_s64(interval, dwrr_idle_interval_ns);
	}

	if (iter > dwrr_max_iteration || unlikely(iter < 0))
	{
		q->round_time[prio] = 0;
		return;
	}

	for (i = 0; i < iter; i++)
		q->round_time[prio] = ewma_round(q->round_time[prio], 0);
}



/*
 * We use this function to account for the true number of bytes sent on wire.
 * 20 = frame check sequence(8B)+Interpacket gap(12B)
 * 4 = Frame check sequence (4B)
 * dwrr_min_pkt_bytes = Minimum Ethernet frame size (64B)
 */
static inline unsigned int skb_size(struct sk_buff *skb)
{
	return max_t(unsigned int, skb->len + 4, dwrr_min_pkt_bytes) + 20;
}

static inline void precompute_ratedata(struct dwrr_rate_cfg *r)
{
	r->shift = 0;
	r->mult = 1;

	if (r->rate_bps > 0)
	{
		r->shift = 15;
		r->mult = div64_u64(8LLU * NSEC_PER_SEC * (1 << r->shift),
				    r->rate_bps);
	}
}

static inline u64 l2t_ns(struct dwrr_rate_cfg *r, unsigned int len_bytes)
{
	return ((u64)len_bytes * r->mult) >> r->shift;
}

static void dropx_marking(struct sk_buff *skb,
		      	   struct dwrr_sched_data *q,
		      	   struct dwrr_class *cl)
{
	struct iphdr* iph = ip_hdr(skb);
	if(cl->len_bytes >= cl->perq_bytes)
		//iph->tos |= INET_ECN_CE;
		INET_ECN_set_ce(skb);
}

static void pmsb_marking(struct sk_buff *skb,
		      	   struct dwrr_sched_data *q,
		      	   struct dwrr_class *cl)
{
	struct iphdr* iph = ip_hdr(skb);
	if(q->sum_len_bytes >= dwrr_port_thresh_bytes && cl->len_bytes >= dwrr_queue_thresh_bytes[cl->id])
		//iph->tos |= INET_ECN_CE;
		INET_ECN_set_ce(skb);
}


void dwrr_qlen_marking(struct sk_buff *skb,
		       struct dwrr_sched_data *q,
		       struct dwrr_class *cl)
{
	struct iphdr* iph = ip_hdr(skb);
	switch (dwrr_ecn_scheme)
	{
		/* Per-queue ECN marking */
		case dwrr_queue_ecn:
		{
			if (cl->len_bytes > dwrr_queue_thresh_bytes[cl->id])
				//iph->tos |= INET_ECN_CE;
				INET_ECN_set_ce(skb);
			break;
		}
		/* Per-port ECN marking */
		case dwrr_port_ecn:
		{
			if (q->sum_len_bytes > dwrr_port_thresh_bytes)
				//iph->tos |= INET_ECN_CE;
				INET_ECN_set_ce(skb);
			break;
		}

		/* Dropx-ECN */
		case dwrr_dropx:
		{	if(dwrr_dropx_ecn)
				dropx_marking(skb, q, cl);
				break;
		}

		/* CEDM
		case dwrr_cedm:
		{
			if (q->sum_len_bytes > dwrr_cedm_thresh_bytes)
				//iph->tos |= INET_ECN_CE;
				INET_ECN_set_ce(skb);
			else if (q->cedm_avgs > 0 && q->sum_len_bytes > dwrr_port_thresh_bytes)
				//iph->tos |= INET_ECN_CE;
				INET_ECN_set_ce(skb);
			break;
		}*/
		default:
		{
			break;
		}
	}
}


static bool codel_should_mark(const struct sk_buff *skb,
	                      struct dwrr_class *cl,
			      s64 now_ns)
{
	bool ok_to_mark;
	codel_time_t now = ns_to_codel_time(now_ns);

	cl->ldelay = ns_to_codel_time(now_ns - skb->tstamp.tv64);

	if (codel_time_before(cl->ldelay, (codel_time_t)dwrr_codel_target) ||
	    cl->len_bytes <= dwrr_max_pkt_bytes)
	{
		/* went below - stay below for at least interval */
		cl->first_above_time = 0;
		return false;
	}

	ok_to_mark = false;
	if (cl->first_above_time == 0)
	{

		cl->first_above_time = now + dwrr_codel_interval;
	}
	else if (codel_time_after(now, cl->first_above_time))
	{
		ok_to_mark = true;
	}

	return ok_to_mark;
}


/* or sizeof_in_bits(rec_inv_sqrt) */
#define REC_INV_SQRT_BITS (8 * sizeof(u16))
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT (32 - REC_INV_SQRT_BITS)

/* Borrow from codel_Newton_step in Linux kernel */
static void codel_Newton_step(struct dwrr_class *cl)
{
	u32 invsqrt = ((u32)cl->rec_inv_sqrt) << REC_INV_SQRT_SHIFT;
	u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
	u64 val = (3LL << 32) - ((u64)cl->count * invsqrt2);

	val >>= 2; /* avoid overflow in following multiply */
	val = (val * invsqrt) >> (32 - 2 + 1);

	cl->rec_inv_sqrt = val >> REC_INV_SQRT_SHIFT;
}

/*
 * CoDel control_law is t + interval/sqrt(count)
 * We maintain in rec_inv_sqrt the reciprocal value of sqrt(count) to avoid
 * both sqrt() and divide operation.
 *
 * Borrow from codel_control_law in Linux kernel
 */
static codel_time_t codel_control_law(codel_time_t t,
				      codel_time_t interval,
				      u32 rec_inv_sqrt)
{
	return t + reciprocal_scale(interval,
				    rec_inv_sqrt << REC_INV_SQRT_SHIFT);
}

static void codel_marking(struct sk_buff *skb, struct dwrr_class *cl)
{
	struct iphdr* iph = ip_hdr(skb);
	s64 now_ns = ktime_get_ns();
	codel_time_t now = ns_to_codel_time(now_ns);
	bool mark = codel_should_mark(skb, cl, now_ns);

	if (cl->marking)
	{
		if (!mark)
		{
			/* sojourn time below target - leave marking state */
			cl->marking = false;
		}
		else if (codel_time_after_eq(now, cl->mark_next))
		{
			/* It's time for the next mark */
			cl->count++;
			codel_Newton_step(cl);
			cl->mark_next = codel_control_law(cl->mark_next,
					  	          dwrr_codel_interval,
					                  cl->rec_inv_sqrt);
		  //iph->tos |= INET_ECN_CE;
			INET_ECN_set_ce(skb);
		}
	}
	else if (mark)
	{
		u32 delta;

		//iph->tos |= INET_ECN_CE;
		INET_ECN_set_ce(skb);
		cl->marking = true;
		/* if min went above target close to when we last went below it
         	 * assume that the drop rate that controlled the queue on the
         	 * last cycle is a good starting point to control it now.
         	 */
		delta = cl->count - cl->lastcount;
 		if (delta > 1 &&
 		    codel_time_before(now - cl->mark_next,
 				      (codel_time_t)dwrr_codel_interval * 16))
 		{
         		cl->count = delta;
             		/* we dont care if rec_inv_sqrt approximation
              		 * is not very precise :
              		 * Next Newton steps will correct it quadratically.
              		 */
         		codel_Newton_step(cl);
 		}
 		else
 		{
 			cl->count = 1;
 			cl->rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
 		}
 		cl->lastcount = cl->count;
 		cl->mark_next = codel_control_law(now,
 						  dwrr_codel_interval,
 						  cl->rec_inv_sqrt);
	}
}

static struct dwrr_class *dwrr_classify(struct sk_buff *skb, struct Qdisc *sch)
{
	struct dwrr_sched_data *q = qdisc_priv(sch);
	struct iphdr* iph = ip_hdr(skb);
	int i, dscp;

	if (unlikely(!(q->queues)))
		return NULL;

	/* Return queue[0] by default*/
	if (unlikely(!iph))
		return &(q->queues[0]);

	dscp = iph->tos >> 2;

	for (i = 0; i < dwrr_real_max_queues; i++)
	{
		if (dscp == dwrr_queue_dscp[i])
			return &(q->queues[i]);
	}

	return &(q->queues[0]);
}

static struct sk_buff *dwrr_peek(struct Qdisc *sch)
{
	return NULL;
}


static s64 tbf_schedule(unsigned int len, struct dwrr_sched_data *q, s64 now)
{
	s64 pkt_ns, toks;

	toks = now - q->time_ns;
	toks = min_t(s64, toks, (s64)l2t_ns(&q->rate, dwrr_bucket_bytes));
	toks += q->tokens;

	pkt_ns = (s64)l2t_ns(&q->rate, len);

	return toks - pkt_ns;
}

int prio_schedule(struct dwrr_sched_data *q)
{
	int i;

	for (i = 0; i < dwrr_max_prio; i++)
	{
		if (!list_empty(&q->active[i]))
			return i;
	}

	return -1;
}

static struct sk_buff *dwrr_dequeue(struct Qdisc *sch)
{
	struct dwrr_sched_data *q = qdisc_priv(sch);
	struct dwrr_class *cl = NULL;
	struct sk_buff *skb = NULL;
	s64 sample, result;
	s64 now = ktime_get_ns();
	s64 bucket_ns = (s64)l2t_ns(&q->rate, dwrr_bucket_bytes);
	unsigned int len;
	struct list_head *active = NULL;
	int prio = prio_schedule(q);
	int i;
	if (prio < 0)
		return NULL;
	else
		active = &q->active[prio];

	while (1)
	{
		cl = list_first_entry(active, struct dwrr_class, alist);
		if (unlikely(!cl))
			return NULL;

		/* get head packet */
		skb = cl->qdisc->ops->peek(cl->qdisc);
		if (unlikely(!skb))
			return NULL;

		len = skb_size(skb);

		/* If this packet can be scheduled by DWRR */
		if (len <= cl->deficit)
		{
			result = tbf_schedule(len, q, now);
			/* If we don't have enough tokens */
			if (result < 0)
			{
				/* For hrtimer absolute mode, we use now + t */
				qdisc_watchdog_schedule_ns(&q->watchdog,
							   now - result,
							   true);
				qdisc_qstats_overlimit(sch);
				return NULL;
			}

			skb = qdisc_dequeue_peeked(cl->qdisc);
			if (unlikely(!skb))
				return NULL;
			q->prio_len_bytes[prio] -= len;
			if (q->prio_len_bytes[prio] == 0)
				q->last_idle_time[prio] = now;

			q->sum_len_bytes -= len;
			sch->q.qlen--;
			cl->len_bytes -= len;
			cl->deficit -= len;
			cl->last_pkt_time = now + l2t_ns(&q->rate, len);

			if (cl->qdisc->q.qlen == 0)
			{
				list_del(&cl->alist);
				sample = cl->last_pkt_time - cl->start_time;
				q->round_time[prio] = ewma_round(q->round_time[prio], sample);
				print_round(q->round_time[prio], sample);
			}

			/* Bucket */
			q->time_ns = now;
			q->tokens = min_t(s64, result, bucket_ns);
			qdisc_unthrottled(sch);
			qdisc_bstats_update(sch, skb);

			/* dequeu equeue length based ECN marking */
			else if (dwrr_enable_dequeue_ecn == dwrr_enable)
				dwrr_qlen_marking(skb, q, cl);


			return skb;
		}

		/* This packet can not be scheduled by DWRR */
		sample = cl->last_pkt_time - cl->start_time;
		q->round_time[prio] = ewma_round(q->round_time[prio], sample);
		cl->start_time = cl->last_pkt_time;
		cl->quantum = dwrr_queue_quantum[cl->id];
		list_move_tail(&cl->alist, active);

		/* WRR */
		if (dwrr_enable_wrr == dwrr_enable)
			cl->deficit = cl->quantum;
		else
			cl->deficit += cl->quantum;

		print_round(q->round_time[prio], sample);
	}

	return NULL;
}


static bool dwrr_buffer_overfill(unsigned int len, struct dwrr_class *cl, struct dwrr_sched_data *q)
{
	int i;
	int temp;
	int cur_max;
	int temp1;
	int temp2;
	cur_max=0;
	int begin;
	begin=1;
	int comp_bytes;
	comp_bytes=dwrr_shared_buffer_bytes;
	if(dwrr_dropx_ecn)
		comp_bytes=dwrr_bdp_bytes;
	if (dwrr_ecn_scheme==dwrr_dropx && dwrr_real_max_queues > 1){
		if(cl->len_bytes + len > cl->perq_bytes){
			if(q->sum_perq + len > comp_bytes){
				for(i=0;i<dwrr_real_max_queues;i++){
					if(i!=cl->id){
						temp1=q->queues[i].perq_bytes - dwrr_queue_thresh_bytes[i];
						temp2=q->queues[cur_max].perq_bytes - dwrr_queue_thresh_bytes[cur_max];
						if(temp1>temp2 || begin==1){
							cur_max=i;
							begin=0;
						}
					}
				}
				if(q->queues[cur_max].perq_bytes < len || (q->queues[cur_max].len_bytes > 0 && q->queues[cur_max].perq_bytes - len  < dwrr_queue_thresh_bytes[cur_max])) {
					if(!dwrr_dropx_ecn)
						return true;
				}
				else{
					cl->perq_bytes+=len;
					q->queues[cur_max].perq_bytes-=len;
				}
			}
			else{
				cl->perq_bytes+=len;
				q->sum_perq+=len;
			}
		}
		if (q->sum_len_bytes + len > dwrr_shared_buffer_bytes)
			return true;
		else
			return false;
	}

	if (dwrr_buffer_mode == dwrr_shared_buffer && q->sum_len_bytes + len > dwrr_shared_buffer_bytes){
			return true;
	}
	else if (dwrr_buffer_mode == dwrr_static_buffer &&
		 cl->len_bytes + len > dwrr_queue_buffer_bytes[cl->id])
		return true;
	else
		return false;
}



static int dwrr_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct dwrr_class *cl = NULL;
	unsigned int len = skb_size(skb); // pkt size
	unsigned int victim_len; //LossPass
	struct dwrr_sched_data *q = qdisc_priv(sch);
	int ret, prio;
	int i;
	int temp;
	int begin;

	cl = dwrr_classify(skb, sch);

		if (likely(cl)){
			prio = dwrr_queue_prio[cl->id];
			if (q->prio_len_bytes[prio] == 0)
				reset_round(q, prio);
		}

	if (unlikely(!cl)){
		qdisc_qstats_drop(sch);
		qdisc_qstats_drop(cl->qdisc);
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}
	else if (dwrr_buffer_overfill(len, cl, q)){
		if(dwrr_ecn_scheme == dwrr_barberq && cl->len_bytes < dwrr_queue_buffer_bytes[cl->id]){
			temp=0;
			for(i=0;i<dwrr_real_max_queues;i++){
				if(i!=cl->id && q->queues[i].len_bytes > temp && q->queues[i].len_bytes >  dwrr_queue_buffer_bytes[i])
					temp=i;
			}
			victim_len = skb_size(qdisc_peek_tail(q->queues[temp].qdisc));
			if (len <= victim_len){
					ret = qdisc_dequeue_tail(q->queues[temp].qdisc);
					if (unlikely(!ret)){
						qdisc_qstats_drop(sch);
						qdisc_qstats_drop(cl->qdisc);
						kfree_skb(skb);
						return NET_XMIT_DROP;
					}
					else{
						sch->q.qlen--;
						q->sum_len_bytes -= victim_len;
						q->prio_len_bytes[dwrr_queue_prio[temp]] -= victim_len;
						q->queues[temp].len_bytes -= victim_len;
						//print_dwrr_sched_data(sch);
						if (q->queues[temp].qdisc->q.qlen == 0)
							list_del(&q->queues[temp].alist);
					}
			}
			else{
				qdisc_qstats_drop(sch);
				qdisc_qstats_drop(cl->qdisc);
				kfree_skb(skb);
				return NET_XMIT_DROP;
			}
		}
		else{
			qdisc_qstats_drop(sch);
			qdisc_qstats_drop(cl->qdisc);
			kfree_skb(skb);
			return NET_XMIT_DROP;
		}
	}

	ret = qdisc_enqueue(skb, cl->qdisc);
	if (unlikely(ret != NET_XMIT_SUCCESS))
	{
		if(dwrr_ecn_scheme==dwrr_dropx){
			q->sum_perq=0;
			for(i=0;i<dwrr_real_max_queues;i++){
				q->queues[i].perq_bytes=dwrr_queue_thresh_bytes[i];
				q->sum_perq+=dwrr_queue_thresh_bytes[i];
			}

		}

		if (likely(net_xmit_drop_count(ret)))
		{
			qdisc_qstats_drop(sch);
			qdisc_qstats_drop(cl->qdisc);
		}
		return ret;
	}




	/* If the queue is empty, insert it to the linked list */
	if (cl->qdisc->q.qlen == 1)
	{
		cl->start_time = ktime_get_ns();
		cl->quantum = dwrr_queue_quantum[cl->id];
		cl->prio = prio;
		cl->deficit = cl->quantum;
		list_add_tail(&cl->alist, &(q->active[cl->prio]));
	}

	/* Update queue sizes (per port/priority/queue) */
	sch->q.qlen++;
	q->sum_len_bytes += len;
	q->prio_len_bytes[cl->prio] += len;
	cl->len_bytes += len;

	//print_dwrr_sched_data(sch);

	/* enqueue queue length based ECN marking */
	else if (dwrr_enable_dequeue_ecn == dwrr_disable)
		dwrr_qlen_marking(skb, q, cl);

	return ret;
}

/* We don't need this */
static unsigned int dwrr_drop(struct Qdisc *sch)
{
	return 0;
}

/* We don't need this */
static int dwrr_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return 0;
}

/* Release Qdisc resources */
static void dwrr_destroy(struct Qdisc *sch)
{
	struct dwrr_sched_data *q = qdisc_priv(sch);
	int i;

	if (likely(q->queues))
	{
		for (i = 0; i < dwrr_real_max_queues && (q->queues[i]).qdisc; i++)
			qdisc_destroy((q->queues[i]).qdisc);
	}
	qdisc_watchdog_cancel(&q->watchdog);
	printk(KERN_INFO "destroy sch_dwrr on %s\n", sch->dev_queue->dev->name);
	//print_dwrr_sched_data(sch);
}

static const struct nla_policy dwrr_policy[TCA_TBF_MAX + 1] = {
	[TCA_TBF_PARMS] = { .len = sizeof(struct tc_tbf_qopt) },
	[TCA_TBF_RTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
	[TCA_TBF_PTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
};

/* We only leverage TC netlink interface to configure rate */
static int dwrr_change(struct Qdisc *sch, struct nlattr *opt)
{
	int err;
	struct dwrr_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_TBF_PTAB + 1];
	struct tc_tbf_qopt *qopt;
	__u32 rate;

	err = nla_parse_nested(tb, TCA_TBF_PTAB, opt, dwrr_policy);
	if(err < 0)
		return err;

	err = -EINVAL;
	if (!tb[TCA_TBF_PARMS])
		goto done;

	qopt = nla_data(tb[TCA_TBF_PARMS]);
	rate = qopt->rate.rate;
	/* convert from bytes/s to b/s */
	q->rate.rate_bps = (u64)rate << 3;
	precompute_ratedata(&q->rate);
	err = 0;

	//printk(KERN_INFO "change sch_dwrr on %s\n", sch->dev_queue->dev->name);
        //print_dwrr_sched_data(sch);
 done:
	return err;
}

/* Initialize Qdisc */
static int dwrr_init(struct Qdisc *sch, struct nlattr *opt)
{
	int i;
	struct dwrr_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child;
	s64 now_ns = ktime_get_ns();

	if(sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	q->tokens = 0;
	q->time_ns = now_ns;
	q->sum_len_bytes = 0;
	q->num_active_queues = 0; // DropX
	q->sum_perq = 0; // Dropx
	qdisc_watchdog_init(&q->watchdog, sch);

	/* Initialize per-priority variables */
	for (i = 0; i < dwrr_max_prio; i++)
	{
		INIT_LIST_HEAD(&q->active[i]);
		q->prio_len_bytes[i] = 0;
		q->round_time[i] = 0;
		q->last_idle_time[i] = now_ns;
	}

	/* Initialize per-queue variables */
	for (i = 0; i < dwrr_real_max_queues; i++)
	{
		/* bfifo is in bytes */
		child = fifo_create_dflt(sch,
					&bfifo_qdisc_ops, dwrr_max_buffer_bytes);
		if (likely(child))
			(q->queues[i]).qdisc = child;
		else
			goto err;

		/* Initialize per-queue variables */
		INIT_LIST_HEAD(&(q->queues[i]).alist);
		(q->queues[i]).id = i;
		(q->queues[i]).len_bytes = 0;
		(q->queues[i]).prio = 0;
		(q->queues[i]).deficit = 0;
		(q->queues[i]).start_time = now_ns;
		(q->queues[i]).last_pkt_time = now_ns;
		(q->queues[i]).quantum = 0;
		(q->queues[i]).count = 0;
		(q->queues[i]).lastcount = 0;
		(q->queues[i]).marking = false;
		(q->queues[i]).rec_inv_sqrt = 0;
		(q->queues[i]).first_above_time = 0;
		(q->queues[i]).mark_next = 0;
		(q->queues[i]).ldelay = 0;
		(q->queues[i]).totpkts = 0;
		(q->queues[i]).droppkts = 0;
		(q->queues[i]).evictpkts = 0;
		(q->queues[i]).mismatchpkts = 0;
		(q->queues[i]).perq_bytes = 0;

	}
	return dwrr_change(sch,opt);
err:
	dwrr_destroy(sch);
	return -ENOMEM;
}

static struct Qdisc_ops dwrr_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	NULL,
	.id		=	"tbf",
	.priv_size	=	sizeof(struct dwrr_sched_data),
	.init		=	dwrr_init,
	.destroy	=	dwrr_destroy,
	.enqueue	=	dwrr_enqueue,
	.dequeue	=	dwrr_dequeue,
	.peek		=	dwrr_peek,
	.drop		=	dwrr_drop,
	.change		=	dwrr_change,
	.dump		=	dwrr_dump,
	.owner 		= 	THIS_MODULE,
};

static int __init dwrr_module_init(void)
{
	if (unlikely(!dwrr_params_init()))
		return -1;

	printk(KERN_INFO "sch_dwrr: start working\n");
	return register_qdisc(&dwrr_ops);
}

static void __exit dwrr_module_exit(void)
{
	dwrr_params_exit();
	unregister_qdisc(&dwrr_ops);
	printk(KERN_INFO "sch_dwrr: stop working\n");
}

module_init(dwrr_module_init);
module_exit(dwrr_module_exit);
MODULE_LICENSE("GPL");

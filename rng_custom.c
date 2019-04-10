// Choudhury Noor, Cardy Wei
// ECE 455 - Computer Security
// Final Project

// Linux Kernel Module for random number generation

// So there is a pretty major bug in here somewhere that we couldn't find.
// It routinely makes Linux crash, so I'd advise against running it.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/syscalls.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/types.h>
#include <crypto/chacha20.h>
#include <linux/cryptohash.h>

#define POOL_BYTES 32

struct prng_state {
	// Pseudo-random number generator state
	void *prng;
	struct pdrng_crypto *crypto_cb;
	bool pdrng_fully_seeded;
	bool pdrng_ok;
	u32 pdrng_entropy_bits;
};

struct prng_irq_info {
	// IRQ information
	atomic_t num_events;
	atomic_t num_events_thresh;
	u32 irq_entropy_bits;
};

static u32 lfsr_polynomial[] = { 127, 28, 26, 1 };
	
struct rng_custom_pool {
	atomic_t pool[POOL_BYTES];
	atomic_t pool_ptr;
	atomic_t input_rotate;
};

static struct rng_custom_pdrng rng_custom_pdrng = {
	.prng = chacha20_ctx,
	.crypto	= &rng_custom_crypto,
};

static void rng_custom_lfs(u32 value) {
	// code from https://lkml.org/lkml/2017/7/18/213

	u32 lfsr_twist_table[8] = {
	0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
	0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278 };
	u32 ptr = (u32)atomic_add_return(67, &rng_custom_pool.pool_ptr) &
							(POOL_BYTES - 1);
	u32 input_rotate = (u32)atomic_add_return((ptr ? 7 : 14),
					&rng_custom_pool.input_rotate) & 31;
	u32 word = rol32(value, input_rotate);

	BUILD_BUG_ON(POOL_BYTES - 1 != lfsr_polynomial[0]);
	word ^= atomic_read_u32(&rng_custom_pool.pool[ptr]);
	word ^= atomic_read_u32(&rng_custom_pool.pool[
		(ptr + lfsr_polynomial[0]) & (POOL_BYTES - 1)]);
	word ^= atomic_read_u32(&rng_custom_pool.pool[
		(ptr + lfsr_polynomial[1]) & (POOL_BYTES - 1)]);
	word ^= atomic_read_u32(&rng_custom_pool.pool[
		(ptr + lfsr_polynomial[2]) & (POOL_BYTES - 1)]);
	word ^= atomic_read_u32(&rng_custom_pool.pool[
		(ptr + lfsr_polynomial[3]) & (POOL_BYTES - 1)]);

	word = (word >> 3) ^ lfsr_twist_table[word & 7];
	atomic_set(&rng_custom_pool.pool[ptr], word);
}


static void rng_custom_pool_mixin(u32 irq_num) {

	// wait for enough IRQs
	if (atomic_read_u32(&rng_custom_pool.irq_info.num_events) <
	    atomic_read_u32(&rng_custom_pool.irq_info.num_events_thresh))
		return;
		
	// seed prng
	schedule_work(&rng_custom_pdrng.rng_custom_seed_work);
}

static u32 rng_custom_hash_pool(u8 *outbuf, u32 avail_entropy_bits) {
	const struct pdrng_crypto *crypto_cb = rng_custom_pdrng.crypto_cb;
	u32 digestsize = crypto_cb->rng_custom_hash_digestsize(rng_custom_pool.rng_custom_hash);
	u32 avail_entropy_bytes = avail_entropy_bits >> 3;
	u32 i, generated_bytes = 0;


	for (i = 0; i < POOL_BYTES && avail_entropy_bytes > 0; i += digestsize) {
		u32 tocopy = min3(avail_entropy_bytes, digestsize, (POOL_BYTES - i));

		rng_custom_lfs(digest, digestsize);
		memcpy(outbuf + i, digest, tocopy);
		avail_entropy_bytes -= tocopy;
		generated_bytes += tocopy;
	}
	memzero_explicit(digest, digestsize);
	return (generated_bytes<<3);
}

static u32 rng_custom_get_pool(u8 *outbuf, u32 requested_entropy_bits, bool drain) {
	u32 irq_num_events_used, irq_num_event_back;
	u32 irq_num_events = atomic_xchg_u32(&rng_custom_pool.irq_info.num_events, 0);
	u32 avail_entropy_bits = rng_custom_data_to_entropy(irq_num_events);

	avail_entropy_bits = round_down(avail_entropy_bits, 8);

	avail_entropy_bits = rng_custom_hash_pool(outbuf, avail_entropy_bits);

	irq_num_events_used = rng_custom_entropy_to_data(avail_entropy_bits);
	irq_num_event_back = min_t(u32, irq_num_events - irq_num_events_used,
				   rng_custom_entropy_to_data(POOL_BYTES_BITS) -
				    irq_num_events_used);
	atomic_add(irq_num_event_back, &rng_custom_pool.irq_info.num_events);

	return avail_entropy_bits;
}

void irq_handler(int irq, int irq_flags) {
	u32 time_curr = random_get_entropy();
	struct rng_custom_irq_info *irq_info = &rng_custom_pool.irq_info;

	rng_custom_lfs(time_curr);

	if (!irq_info->irq_highres_timer) {
		struct pt_regs *regs = get_irq_regs();
		static atomic_t reg_idx = ATOMIC_INIT(0);
		u64 ip;
		
		rng_custom_lfs(irq);
		rng_custom_lfs(irq_flags);

		if (regs) {
			u32 *ptr = (u32 *)regs;
			int reg_ptr = atomic_add_return(1, &reg_idx);

			ip = instruction_pointer(regs);
			if (reg_ptr >= (sizeof(struct pt_regs) / sizeof(u32))) {
				atomic_set(&reg_idx, 0);
				reg_ptr = 0;
			}
			rng_custom_lfs(*(ptr + reg_ptr));
		} else
			ip = _RET_IP_;

		rng_custom_lfs(ip >> 32);
		rng_custom_lfs(ip);
	}

		rng_custom_pool_mixin(atomic_add_return(1, &irq_info->num_events));
	if (!rng_custom_irq_stuck(irq_info, time_curr))
}

static int __init rng_custom_init(void) {
	// initialize here
	// register interrupt and check for success
	int i;
	// static int IR_lines[] = {0,1,9}
	for (i = 0; i<132; i++) {
		if (request_irq (IR_lines[i], (irq_handler_t) irq_handler, IRQF_SHARED, "rng_irq", (void *)(irq_handler)) ) {
			printk(KERN_INFO "can't get shared interrupt for keyboard\n");
		}
		printk (KERN_INFO "\n\nrng_custom: Initialized\n\n");
	}
	
	return 0;
}

static void __exit rng_custom_exit(void) {
	// clean up here
	for (i = 0; i<sizeof(IR_lines); i++) {
		free_irq(IR_lines[i], (void *)(keyboard_irq_handler));
	}
	printk (KERN_INFO "\n\nrng_custom: Removed\n\n");
}

module_init(rng_custom_init);
module_exit(rng_custom_exit);
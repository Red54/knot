#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

void *memzero(void *s, size_t n)
{
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t volatile_memset = memset;
	return volatile_memset(s, 0, n);
}

#include <knot/modules/rrl/kru.h>
#define KRU_DECAY_BITS 16

/*
void test_decay32(void)
{
#if defined(KRU_IMPL_min32bit)
	struct load_cl l = { .loads[0] = -1, .time = 0 };
	for (uint32_t time = 0; time < 1030; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08zx\n", time, (size_t)l.loads[0]);
	}
#elif defined(KRU_IMPL_median32bit) || defined(KRU_IMPL_ss32bit)
	struct load_cl l = { .loads[0] = (1ull<<31) - 1, .loads[1] = -(1ll<<31), .time = 0 };
	for (uint32_t time = 0; time < 850; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08d %08d\n", time, (int)l.loads[0], (int)l.loads[1]);
	}
#elif defined(KRU_IMPL_median16bit_simd)
	struct load_cl l = { .loads[0] = (1ull<<15) - 1, .loads[1] = -(1ll<<15), .time = 0 };
	for (uint32_t time = 0; time < 340; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08d %08d\n", time, (int)l.loads[0], (int)l.loads[1]);
	}
#elif defined(KRU_IMPL_ss16bit) || defined(KRU_IMPL_ss16bit_simd)
	struct load_cl l = { .loads[0] = (1ull<<16) - 1, .loads[1] = (1ll<<16) - 1, .time = 0 };
	for (uint32_t time = 0; time < 340; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08d %08d\n", time, (int)l.loads[0], (int)l.loads[1]);
	}
#else
	assert(0);
#endif
}
*/

#ifdef HASH_KEY_T
void test_hash(void)
{
	HASH_KEY_T key;
	(void) HASH_INIT(key);

	char str[] = "abcd";
	HASH_FROM_BUF(key, str, sizeof(str));
	// hashes[0] = -1;
	// hashes[1] = 0;
	// hashes[2] = -1;

	for (size_t i = 0; i < HASH_BITS; i += 7) {
		printf("%ld\n", HASH_GET_BITS(7));
	}
}
#endif


/*===  benchmarking manageable number of attackers  ===*/

struct test_ctx {
	struct kru *kru;
	uint32_t time;        // last time
	uint32_t begin_time;  // time when stats were cleared
	uint32_t price;       // price of all queries
	size_t cnt;           // count of categories
	struct test_cat {     // categories of users
		char *name;
		uint64_t id_min, id_max;  // there is (id_max - id_min + 1) unique users in the category
		uint64_t freq;            // number of queries per tick from the category (each from random user)
		uint64_t passed, total;   // accumulating statistic variables
	} *cats;
};

void test_stage(struct test_ctx *ctx, uint32_t dur) {
	uint64_t freq_bounds[ctx->cnt];
	freq_bounds[0] = ctx->cats[0].freq;
	for (size_t cat = 1; cat < ctx->cnt; ++cat) {
		freq_bounds[cat] = freq_bounds[cat-1] + ctx->cats[cat].freq;
	}

	for (uint64_t end_time = ctx->time + dur; ctx->time < end_time; ctx->time++) {
		for (uint64_t i = 0; i < freq_bounds[ctx->cnt-1]; i++) {
			uint64_t rnd = random() % freq_bounds[ctx->cnt-1];  // TODO initialize random generator
			size_t cat;
			for (cat = 0; freq_bounds[cat] <= rnd; cat++);

			uint64_t key[2] = {0,};
			key[0] = random() % (ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1) + ctx->cats[cat].id_min;

			ctx->cats[cat].total++;
			ctx->cats[cat].passed += !KRU.limited(ctx->kru, (char *)key, ctx->time, ctx->price);
		}
	}
}

void test_clear_stats(struct test_ctx *ctx) {
	for (size_t i = 0; i < ctx->cnt; i++) {
		ctx->cats[i].passed = 0;
		ctx->cats[i].total = 0;
	}
	ctx->begin_time = ctx->time;
}

void test_print_stats(struct test_ctx *ctx) {
	printf("TICKS %" PRIu32 "-%" PRIu32, ctx->begin_time, ctx->time - 1);

	int price_log = 0;
	for (uint32_t price = ctx->price; price >>= 1; price_log++);
	if (ctx->price == (1 << price_log)) {
		printf(", price 2^%d\n", price_log);
	} else {
		printf(", price 0x%x\n", ctx->price);
	}

	uint32_t dur = ctx->time - ctx->begin_time;
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		uint64_t users = ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1;
		char name_users[30];
		snprintf(name_users, sizeof(name_users), "%s (%" PRIu64 "):", ctx->cats[cat].name, users);

		printf("  %-25spassed: %8.4f %%,    per tick:%11.2f /%11.2f,    per tick and user:%8.2f /%10.2f\n",
				name_users,
				100.0 * ctx->cats[cat].passed / ctx->cats[cat].total,
				(float)ctx->cats[cat].passed / dur,         (float)ctx->cats[cat].total / dur,
				(float)ctx->cats[cat].passed / dur / users, (float)ctx->cats[cat].total / dur / users);
	}
	printf("\n");

	test_clear_stats(ctx);
}

#define TEST_STAGE(duration, ...) { \
	uint64_t freq[] = {__VA_ARGS__}; \
	for (size_t i = 0; i < sizeof(cats) / sizeof(*cats); i++) cats[i].freq = freq[i]; \
	test_stage(&ctx, duration); \
	test_print_stats(&ctx); }

void test_single_attacker(void) {
	struct kru *kru = KRU.create(16);

	struct test_cat cats[] = {
		{ "normal",       1,1000  },   // normal queries come from 1000 different addreses indexed 1-1000
		{ "attackers", 1001,1001  }    // attacker use only one address indexed 1001
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(*cats),
		.price = 1<<(KRU_DECAY_BITS
				-7
#if defined(KRU_IMPL_median32bit) || defined(KRU_IMPL_median16bit_simd)
				-1
#endif
			)
	};
	test_clear_stats(&ctx);

	// in each out of 10 ticks send around 1000 queries from random normal addresses and 1000000 from the attacker
	TEST_STAGE( 10,    1000, 1000000); // (duration, normal, attackers)

	TEST_STAGE( 10,    1000, 1000000);
	TEST_STAGE( 100,   1000, 100000);
	TEST_STAGE( 100,   1000, 10000);
	TEST_STAGE( 100,   1000, 1000);
	TEST_STAGE( 100,   1000, 100);
	TEST_STAGE( 100,   1000, 10);
	TEST_STAGE( 10000, 1000, 1);  // both categories have the same frequency per user

	TEST_STAGE( 100,   1000, 10000); // another attack after a period without limitation

	free(kru);
}

#undef TEST_STAGE

void test_multi_attackers(void) {

	struct kru *kru = KRU.create(15);

	struct test_cat cats[] = {
		{ "normal",         1,100000,  100000 },   // 100000 normal queries per tick, ~1 per user
		{ "attackers", 100001,100001,  10     }    // 1 attacker, 10 queries per tick; both will rise by the same factor
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(*cats),
		.price = 1<<(KRU_DECAY_BITS
				-7
#if defined(KRU_IMPL_median32bit) || defined(KRU_IMPL_median16bit_simd)
				-1
#endif
			)
	};
	test_clear_stats(&ctx);

	for (size_t i = 0; i < 17; i++) {
		// hidden ticks with new setting, not counted to stats
		test_stage(&ctx, 10);
		test_clear_stats(&ctx);

		// counted ticks
		test_stage(&ctx, 10);
		test_print_stats(&ctx);

		// double attackers, keep the same number of queries per attacker
		cats[1].id_max += cats[1].id_max - cats[1].id_min + 1;  // new ids were unused so far
		cats[1].freq *= 2;
	}

	free(kru);
}


/*=== benchmarking time performance ===*/

#define TIMED_TESTS_TABLE_SIZE_LOG        16
#define TIMED_TESTS_PRICE           (1 <<  9)
#define TIMED_TESTS_QUERIES         (1 << 26) // 28
#define TIMED_TESTS_MAX_THREADS           12
#define TIMED_TESTS_WAIT_BEFORE_SEC        2  // 60

struct timed_test_ctx {
	struct kru *kru;
	uint64_t first_query, increment;
	int key_mult;
};


void *timed_runnable(void *arg) {
	struct timed_test_ctx *ctx = arg;
	uint64_t key[2] = {0,};

	for (uint64_t i = ctx->first_query; i < TIMED_TESTS_QUERIES; i += ctx->increment) {
		struct timespec now_ts = {0};
		clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);
		uint32_t now_msec = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;

		key[0] = i * ctx->key_mult;
		KRU.limited(ctx->kru, (char *)key, now_msec, TIMED_TESTS_PRICE);
	}
	return NULL;
}

void timed_tests() {
	struct kru *kru;
	struct timed_test_ctx ctx[TIMED_TESTS_MAX_THREADS];
	pthread_t thr[TIMED_TESTS_MAX_THREADS];
	struct timespec begin_ts, end_ts;
	uint64_t diff_nsec;
	struct timespec wait_ts = {TIMED_TESTS_WAIT_BEFORE_SEC, 0};


	for (int threads = 1; threads <= TIMED_TESTS_MAX_THREADS; threads++) {
		for (int collide = 0; collide < 2; collide++) {
			nanosleep(&wait_ts, NULL);
			printf("%3d threads, %-15s:  ", threads, (collide ? "single query" : "unique queries"));

			kru = KRU.create(TIMED_TESTS_TABLE_SIZE_LOG);
			clock_gettime(CLOCK_REALTIME, &begin_ts);

			for (int t = 0; t < threads; t++) {
				ctx[t].kru = kru;
				ctx[t].first_query = t;
				ctx[t].increment  = threads;
				ctx[t].key_mult = 1 - collide;;
				pthread_create(thr + t, NULL, &timed_runnable, ctx + t);
			}

			for (int t = 0; t < threads; t++) {
				pthread_join(thr[t], NULL);
			}

			clock_gettime(CLOCK_REALTIME, &end_ts);
			free(kru);

			diff_nsec = (end_ts.tv_sec - begin_ts.tv_sec) * 1000000000ll + end_ts.tv_nsec - begin_ts.tv_nsec;
			double diff_sec = diff_nsec / 1000000000.0;
			printf("%7.2f MQPS,  %7.2f MQPS per thread,  %2.4f s total\n",
				TIMED_TESTS_QUERIES / diff_sec / 1000000,
				TIMED_TESTS_QUERIES / diff_sec / 1000000 / threads,
				diff_sec);
		}
		printf("\n");
	}
}


/*===*/

int main(int argc, char **argv)
{
	//test_single_attacker();
	//test_multi_attackers();
	timed_tests();

	// struct kru kru __attribute__((unused));
	// test_decay32();
	// test_hash();
	return 0;
}

// Bridge between libOTe's SoftSpokenOT and the Rust DKLST baseline.
//
// libOTe is a two-party coroutine library: `sender.send(...)` and `receiver.receive(...)` must be
// driven concurrently. We therefore run the two halves with `macoro::when_all_ready` over a
// `coproto::LocalAsyncSocket` pair, which keeps everything on a single thread so the measured
// wall time is directly comparable to the sequential single-threaded measurements of the rest of
// this project.
//
// The interface is deliberately narrow: the caller passes the receiver's choice bits and gets the
// raw pads out. All of the DKLST logic (Impagliazzo-Naor encoding, consistency check, share
// combination) stays in Rust, so the only thing that changes between the two backends is the OT
// library.
//
// Wire accounting: `coproto::Socket::bytesSent()` is read on both legs, so the byte counts are
// measured rather than derived from a formula.
//
// Build (standalone check): see `build.rs`; or
//   g++ -O3 -std=c++20 -DLIBOTE_SHIM_MAIN libote_shim.cc $(libote-link-flags) -o ot_bench

#include <cstdint>
#include <cstring>
#include <chrono>
#include <exception>
#include <vector>

#include <coproto/Socket/LocalAsyncSock.h>
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>

namespace
{
	using osuCrypto::BitVector;
	using osuCrypto::block;
	using osuCrypto::DefaultBaseOT;
	using osuCrypto::PRNG;
	using osuCrypto::SoftSpokenMalOtReceiver;
	using osuCrypto::SoftSpokenMalOtSender;

	/// One ordered pair's persistent material: the base OTs. Extensions reuse them.
	struct Pair
	{
		SoftSpokenMalOtSender sender;
		SoftSpokenMalOtReceiver receiver;
		uint32_t field_bits = 2;
	};

	uint64_t now_ns()
	{
		using namespace std::chrono;
		return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
	}

	void fail(int32_t* ok)
	{
		if (ok)
			*ok = 0;
	}
}

extern "C"
{
	/// Timing and wire statistics of one operation.
	struct libote_stats
	{
		uint64_t wall_ns;
		uint64_t bytes_sender;   // extension sender -> extension receiver
		uint64_t bytes_receiver; // extension receiver -> extension sender
		int32_t ok;
	};

	const char* libote_shim_version()
	{
		return "libOTe SoftSpokenMalOtExt";
	}

	/// Number of base OTs a `Pair` consumes (the SoftSpokenOT seed count, 128).
	uint64_t libote_base_ot_count()
	{
		SoftSpokenMalOtSender probe;
		return probe.baseOtCount();
	}

	/// Run the base OTs for one ordered pair. Returns an opaque handle, or null on failure.
	void* libote_pair_new(uint32_t field_bits, libote_stats* stats)
	{
		try
		{
			auto* pair = new Pair();
			pair->field_bits = field_bits;
			pair->sender = SoftSpokenMalOtSender(field_bits);
			pair->receiver = SoftSpokenMalOtReceiver(field_bits);

			auto socks = coproto::LocalAsyncSocket::makePair();
			PRNG prng(osuCrypto::sysRandomSeed());

			// In the random-OT convention the roles are flipped: the extension receiver plays the
			// base-OT sender (it learns both blocks per index) and publishes nothing else.
			DefaultBaseOT baseSender, baseReceiver;

			std::vector<std::array<block, 2>> recvBase(pair->receiver.baseOtCount());
			std::vector<block> sendBase(pair->sender.baseOtCount());
			BitVector baseChoices(pair->sender.baseOtCount());
			baseChoices.randomize(prng);

			auto started = now_ns();
			auto results = coproto::sync_wait(macoro::when_all_ready(
				baseSender.send(recvBase, prng, socks[1]),
				baseReceiver.receive(baseChoices, sendBase, prng, socks[0])));
			std::get<0>(results).result();
			std::get<1>(results).result();
			auto elapsed = now_ns() - started;

			pair->receiver.setBaseOts(recvBase);
			pair->sender.setBaseOts(sendBase, baseChoices);

			if (stats)
			{
				stats->wall_ns = elapsed;
				stats->bytes_sender = socks[0].bytesSent();
				stats->bytes_receiver = socks[1].bytesSent();
				stats->ok = 1;
			}
			return pair;
		}
		catch (const std::exception& error)
		{
			std::fprintf(stderr, "libote_pair_new: %s\n", error.what());
			fail(stats ? &stats->ok : nullptr);
			return nullptr;
		}
	}

	void libote_pair_free(void* handle)
	{
		delete static_cast<Pair*>(handle);
	}

	/// One SoftSpokenOT extension of `n` 128-bit OTs.
	///
	/// `choices` holds `ceil(n/8)` bytes, bit `i` (LSB first) selecting the receiver's block of
	/// OT `i`. `v0`/`v1` receive the sender's two blocks per OT (16 bytes each), `vx` the
	/// receiver's block. All three buffers are `n * 16` bytes.
	int32_t libote_extend(
		void* handle,
		const uint8_t* choices,
		uint64_t n,
		uint8_t* v0,
		uint8_t* v1,
		uint8_t* vx,
		libote_stats* stats)
	{
		if (!handle || !choices || !v0 || !v1 || !vx || n == 0)
		{
			fail(stats ? &stats->ok : nullptr);
			return 0;
		}
		try
		{
			auto* pair = static_cast<Pair*>(handle);

			BitVector choiceBits(n);
			for (uint64_t i = 0; i < n; ++i)
				choiceBits[i] = (choices[i / 8] >> (i % 8)) & 1;

			// SoftSpokenOT requires the message buffers to be 32-byte aligned, hence the
			// `AlignedUnVector` rather than `std::vector`.
			osuCrypto::AlignedUnVector<std::array<block, 2>> msgs(n);
			osuCrypto::AlignedUnVector<block> recvMsgs(n);

			auto socks = coproto::LocalAsyncSocket::makePair();
			PRNG prng(osuCrypto::sysRandomSeed());

			auto started = now_ns();
			auto results = coproto::sync_wait(macoro::when_all_ready(
				pair->sender.send(msgs, prng, socks[0]),
				pair->receiver.receive(choiceBits, recvMsgs, prng, socks[1])));
			std::get<0>(results).result();
			std::get<1>(results).result();
			auto elapsed = now_ns() - started;

			auto bytesSender = static_cast<uint64_t>(socks[0].bytesSent());
			auto bytesReceiver = static_cast<uint64_t>(socks[1].bytesSent());

			for (uint64_t i = 0; i < n; ++i)
			{
				std::memcpy(v0 + 16 * i, &msgs[i][0], 16);
				std::memcpy(v1 + 16 * i, &msgs[i][1], 16);
				std::memcpy(vx + 16 * i, &recvMsgs[i], 16);
			}

			if (stats)
			{
				stats->wall_ns = elapsed;
				stats->bytes_sender = bytesSender;
				stats->bytes_receiver = bytesReceiver;
				stats->ok = 1;
			}
			return 1;
		}
		catch (const std::exception& error)
		{
			std::fprintf(stderr, "libote_extend: %s\n", error.what());
			fail(stats ? &stats->ok : nullptr);
			return 0;
		}
	}
}

#ifdef LIBOTE_SHIM_MAIN
#include <cstdio>
#include <cstdlib>

// Standalone self-check / micro-benchmark: `./ot_bench [n] [reps] [field_bits]`.
int main(int argc, char** argv)
{
	uint64_t n = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 2688;
	uint64_t reps = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 10;
	uint32_t field_bits = argc > 3 ? (uint32_t)std::strtoul(argv[3], nullptr, 10) : 2;

	libote_stats setup{};
	void* pair = libote_pair_new(field_bits, &setup);
	if (!pair)
	{
		std::fprintf(stderr, "base OT setup failed\n");
		return 1;
	}
	std::printf("setup    %.3f ms, %llu B ->, %llu B <-\n",
		setup.wall_ns / 1e6,
		(unsigned long long)setup.bytes_sender,
		(unsigned long long)setup.bytes_receiver);

	std::vector<uint8_t> choices((n + 7) / 8, 0);
	std::vector<uint8_t> v0(16 * n), v1(16 * n), vx(16 * n);

	double total = 0;
	uint64_t bytes = 0;
	for (uint64_t rep = 0; rep < reps; ++rep)
	{
		for (uint64_t i = 0; i < n; ++i)
		{
			auto bit = (uint8_t)(rand() & 1);
			choices[i / 8] = (uint8_t)((choices[i / 8] & ~(1u << (i % 8))) | (bit << (i % 8)));
		}
		libote_stats stats{};
		if (!libote_extend(pair, choices.data(), n, v0.data(), v1.data(), vx.data(), &stats))
		{
			std::fprintf(stderr, "extension failed\n");
			return 1;
		}
		total += stats.wall_ns / 1e6;
		bytes = stats.bytes_sender + stats.bytes_receiver;
	}
	std::printf("extend   %.3f ms/instance (%llu OTs), wire %llu B, %.1f bytes/OT\n",
		total / reps, (unsigned long long)n,
		(unsigned long long)bytes, (double)bytes / n);
	libote_pair_free(pair);
	return 0;
}
#endif

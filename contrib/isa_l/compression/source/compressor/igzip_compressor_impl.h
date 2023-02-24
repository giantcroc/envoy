#pragma once

#include "envoy/compression/compressor/compressor.h"

#include "contrib/isa_l/compression/source/common/base.h"
#include "isa-l.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Igzip {
namespace Compressor {

const uint64_t memory_sizes[15] = {
    ISAL_DEF_LVL1_MIN,         ISAL_DEF_LVL1_SMALL,       ISAL_DEF_LVL1_MEDIUM,
    ISAL_DEF_LVL1_LARGE,       ISAL_DEF_LVL1_EXTRA_LARGE, ISAL_DEF_LVL2_MIN,
    ISAL_DEF_LVL2_SMALL,       ISAL_DEF_LVL2_MEDIUM,      ISAL_DEF_LVL2_LARGE,
    ISAL_DEF_LVL2_EXTRA_LARGE, ISAL_DEF_LVL3_MIN,         ISAL_DEF_LVL3_SMALL,
    ISAL_DEF_LVL3_MEDIUM,      ISAL_DEF_LVL3_LARGE,       ISAL_DEF_LVL3_EXTRA_LARGE};

/**
 * Implementation of compressor's interface.
 */
class IgzipCompressorImpl : public Common::Base, public Envoy::Compression::Compressor::Compressor {
public:
  IgzipCompressorImpl();

  IgzipCompressorImpl(uint64_t chunk_size);

  // Note that only three compression levels supported in isa-l
  enum class CompressionLevel : int64_t {
    Best = 3,
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Speed = 1,
    Standard = 2,
  };

  void init(CompressionLevel level, int64_t window_bits, int64_t memory_level);

  // Compression::Compressor::Compressor
  void compress(Buffer::Instance& buffer, Envoy::Compression::Compressor::State state) override;

private:
  bool deflateNext();
  void process(Buffer::Instance& output_buffer, int64_t flush_state);
};

} // namespace Compressor
} // namespace Igzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy

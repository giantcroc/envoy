#include "contrib/isa_l/compression/source/compressor/igzip_compressor_impl.h"

#include <memory>

#include "envoy/common/exception.h"

#include "source/common/common/assert.h"

#include "absl/container/fixed_array.h"
#include "isa-l.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Igzip {
namespace Compressor {

IgzipCompressorImpl::IgzipCompressorImpl() : IgzipCompressorImpl(4096) {}

IgzipCompressorImpl::IgzipCompressorImpl(uint64_t chunk_size)
    : Common::Base(chunk_size, [](isal_zstream* z) {
        free(z->level_buf);
        delete z;
      }) {}

void IgzipCompressorImpl::init(CompressionLevel comp_level, int64_t window_bits,
                               int64_t memory_level) {
  ASSERT(initialized_ == false);
  isal_deflate_init(zstream_ptr_.get());
  zstream_ptr_->avail_out = chunk_size_;
  zstream_ptr_->next_out = chunk_char_ptr_.get();
  zstream_ptr_->gzip_flag = IGZIP_GZIP;
  zstream_ptr_->hist_bits = window_bits;

  if (comp_level == CompressionLevel::Level1) {
    zstream_ptr_->level = 1;
  } else if (comp_level == CompressionLevel::Level2) {
    zstream_ptr_->level = 2;
  } else {
    zstream_ptr_->level = 3;
  }

  uint64_t buf_size = 0;
  uint64_t joint_index = (zstream_ptr_->level - 1) * 5 + memory_level - 1;
  switch (joint_index) {
  case 0:
    buf_size = ISAL_DEF_LVL1_MIN;
    break;
  case 1:
    buf_size = ISAL_DEF_LVL1_SMALL;
    break;
  case 2:
    buf_size = ISAL_DEF_LVL1_MEDIUM;
    break;
  case 3:
    buf_size = ISAL_DEF_LVL1_LARGE;
    break;
  case 4:
    buf_size = ISAL_DEF_LVL1_EXTRA_LARGE;
    break;
  case 5:
    buf_size = ISAL_DEF_LVL2_MIN;
    break;
  case 6:
    buf_size = ISAL_DEF_LVL2_SMALL;
    break;
  case 7:
    buf_size = ISAL_DEF_LVL2_MEDIUM;
    break;
  case 8:
    buf_size = ISAL_DEF_LVL2_LARGE;
    break;
  case 9:
    buf_size = ISAL_DEF_LVL2_EXTRA_LARGE;
    break;
  case 10:
    buf_size = ISAL_DEF_LVL3_MIN;
    break;
  case 11:
    buf_size = ISAL_DEF_LVL3_SMALL;
    break;
  case 12:
    buf_size = ISAL_DEF_LVL3_MEDIUM;
    break;
  case 13:
    buf_size = ISAL_DEF_LVL3_LARGE;
    break;
  case 14:
    buf_size = ISAL_DEF_LVL3_EXTRA_LARGE;
    break;
  default:
    buf_size = ISAL_DEF_LVL3_EXTRA_LARGE;
  }
  zstream_ptr_->level_buf = static_cast<uint8_t*>(malloc(buf_size));
  zstream_ptr_->level_buf_size = buf_size;
  initialized_ = true;
}

void IgzipCompressorImpl::compress(Buffer::Instance& buffer,
                                   Envoy::Compression::Compressor::State state) {
  ASSERT(initialized_);
  for (const Buffer::RawSlice& input_slice : buffer.getRawSlices()) {
    zstream_ptr_->avail_in = input_slice.len_;
    zstream_ptr_->next_in = static_cast<uint8_t*>(input_slice.mem_);
    process(buffer, NO_FLUSH);
    buffer.drain(input_slice.len_);
  }

  process(buffer, state == Envoy::Compression::Compressor::State::Finish ? FULL_FLUSH : SYNC_FLUSH);
}

bool IgzipCompressorImpl::deflateNext() {
  const int result = isal_deflate(zstream_ptr_.get());

  RELEASE_ASSERT(result == COMP_OK, "");

  return zstream_ptr_->avail_out == 0;
}

void IgzipCompressorImpl::process(Buffer::Instance& output_buffer, int64_t flush_state) {
  zstream_ptr_->end_of_stream = (flush_state == FULL_FLUSH);
  zstream_ptr_->flush = flush_state;
  while (deflateNext()) {
    updateOutput(output_buffer);
  }
  RELEASE_ASSERT(zstream_ptr_->avail_in == 0, "");

  if (flush_state == SYNC_FLUSH || flush_state == FULL_FLUSH) {
    updateOutput(output_buffer);
  }
}

} // namespace Compressor
} // namespace Igzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy

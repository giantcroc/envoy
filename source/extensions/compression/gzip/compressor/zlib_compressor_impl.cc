#include "source/extensions/compression/gzip/compressor/zlib_compressor_impl.h"

#include <memory>

#include "envoy/common/exception.h"

#include "source/common/common/assert.h"

#include "absl/container/fixed_array.h"

// #include "zlib.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Gzip {
namespace Compressor {

ZlibCompressorImpl::ZlibCompressorImpl() : ZlibCompressorImpl(4096) {}

ZlibCompressorImpl::ZlibCompressorImpl(uint64_t chunk_size)
    : Zlib::Base(chunk_size, [](isal_zstream* z) {
        free(z->level_buf);
        delete z;
      }) {
}

void ZlibCompressorImpl::init(CompressionLevel comp_level, CompressionStrategy comp_strategy,
                              int64_t window_bits, uint64_t memory_level = 8) {
  ASSERT(initialized_ == false);
  (void)comp_strategy;
  (void)window_bits;
  (void)memory_level;
  isal_deflate_init(zstream_ptr_.get());
  zstream_ptr_->avail_out = chunk_size_;
  zstream_ptr_->next_out = chunk_char_ptr_.get();
  zstream_ptr_->gzip_flag = IGZIP_GZIP;
  auto level = static_cast<int64_t>(comp_level);
  if (level == 1) {
		zstream_ptr_->level = 1;
		zstream_ptr_->level_buf = static_cast<uint8_t *>(malloc(ISAL_DEF_LVL1_DEFAULT));
		zstream_ptr_->level_buf_size = ISAL_DEF_LVL1_DEFAULT;
	}else if (level == 2) {
		zstream_ptr_->level = 2;
		zstream_ptr_->level_buf = static_cast<uint8_t *>(malloc(ISAL_DEF_LVL2_DEFAULT));
		zstream_ptr_->level_buf_size = ISAL_DEF_LVL2_DEFAULT;		
  }else if (level == 3) {
		zstream_ptr_->level = 3;
		zstream_ptr_->level_buf = static_cast<uint8_t *>(malloc(ISAL_DEF_LVL3_DEFAULT));
		zstream_ptr_->level_buf_size = ISAL_DEF_LVL3_DEFAULT;		
	}
  else{
    zstream_ptr_->level = 0;
		zstream_ptr_->level_buf = nullptr;
		zstream_ptr_->level_buf_size = ISAL_DEF_LVL0_DEFAULT;
  }

  initialized_ = true;
}

void ZlibCompressorImpl::compress(Buffer::Instance& buffer,
                                  Envoy::Compression::Compressor::State state) {
  for (const Buffer::RawSlice& input_slice : buffer.getRawSlices()) {
    zstream_ptr_->avail_in = input_slice.len_;
    zstream_ptr_->next_in = static_cast<uint8_t*>(input_slice.mem_);
    // Z_NO_FLUSH tells the compressor to take the data in and compresses it as much as possible
    // without flushing it out. However, if the data output is greater or equal to the allocated
    // chunk size, process() outputs it to the end of the buffer. This is fine, since at the next
    // step, the buffer is drained from the beginning of the buffer by the size of input.
    process(buffer, NO_FLUSH);
    buffer.drain(input_slice.len_);
  }
  
  process(buffer, state == Envoy::Compression::Compressor::State::Finish ? FULL_FLUSH : SYNC_FLUSH);
}

bool ZlibCompressorImpl::deflateNext(int64_t flush_state) {
  (void)flush_state;
  const int result = isal_deflate(zstream_ptr_.get());

  RELEASE_ASSERT(result == COMP_OK, "");

  return zstream_ptr_->avail_out == 0;
}

void ZlibCompressorImpl::process(Buffer::Instance& output_buffer, int64_t flush_state) {
  zstream_ptr_->end_of_stream = (flush_state == FULL_FLUSH);
  while (deflateNext(flush_state)) {
    if (zstream_ptr_->avail_out == 0) {
      updateOutput(output_buffer);
    }
  }
  assert(zstream_ptr_->avail_in == 0);

  if (flush_state == SYNC_FLUSH || flush_state == FULL_FLUSH) {
    updateOutput(output_buffer);
  }
}

} // namespace Compressor
} // namespace Gzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy

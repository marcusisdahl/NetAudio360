// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_sbc.h"

#include <math.h>
#include <string.h>

namespace bt {

namespace {

// Analysis window for 8 subbands (A2DP Appendix B, prototype filter
// coefficients for M = 8, table "Proto_8_80"). The sign changes every 16
// taps are part of the table.
const float kProto8[80] = {
  0.00000000E+00f, 1.56575398E-04f, 3.43256425E-04f, 5.54620202E-04f,
  8.23919506E-04f, 1.13992507E-03f, 1.47640169E-03f, 1.78371725E-03f,
  2.01182542E-03f, 2.10371989E-03f, 1.99454554E-03f, 1.61656283E-03f,
  9.02154502E-04f, -1.78805361E-04f, -1.64973098E-03f, -3.49717454E-03f,
  5.65949473E-03f, 8.02941163E-03f, 1.04584443E-02f, 1.27472335E-02f,
  1.46525263E-02f, 1.59045603E-02f, 1.62208471E-02f, 1.53184106E-02f,
  1.29371806E-02f, 8.85757540E-03f, 2.92408442E-03f, -4.91578024E-03f,
  -1.46404076E-02f, -2.61098752E-02f, -3.90751381E-02f, -5.31873032E-02f,
  6.79989431E-02f, 8.29847578E-02f, 9.75753918E-02f, 1.11196689E-01f,
  1.23264548E-01f, 1.33264415E-01f, 1.40753505E-01f, 1.45389847E-01f,
  1.46955068E-01f, 1.45389847E-01f, 1.40753505E-01f, 1.33264415E-01f,
  1.23264548E-01f, 1.11196689E-01f, 9.75753918E-02f, 8.29847578E-02f,
  -6.79989431E-02f, -5.31873032E-02f, -3.90751381E-02f, -2.61098752E-02f,
  -1.46404076E-02f, -4.91578024E-03f, 2.92408442E-03f, 8.85757540E-03f,
  1.29371806E-02f, 1.53184106E-02f, 1.62208471E-02f, 1.59045603E-02f,
  1.46525263E-02f, 1.27472335E-02f, 1.04584443E-02f, 8.02941163E-03f,
  -5.65949473E-03f, -3.49717454E-03f, -1.64973098E-03f, -1.78805361E-04f,
  9.02154502E-04f, 1.61656283E-03f, 1.99454554E-03f, 2.10371989E-03f,
  2.01182542E-03f, 1.78371725E-03f, 1.47640169E-03f, 1.13992507E-03f,
  8.23919506E-04f, 5.54620202E-04f, 3.43256425E-04f, 1.56575398E-04f
};

// Loudness offsets for 8 subbands by sampling frequency (Appendix B).
const int kOffset8[4][8] = {
  {-2, 0, 0, 0, 0, 0, 0, 1},
  {-3, 0, 0, 0, 0, 0, 1, 2},
  {-4, 0, 0, 0, 0, 0, 1, 2},
  {-4, 0, 0, 0, 0, 0, 1, 2}
};

// Analysis matrix cos((k + 0.5)(i - 4) pi / 8), built once.
float g_matrix[8][16];
bool g_matrix_ready = false;

void BuildMatrix() {
  if (g_matrix_ready) return;
  const double pi = 3.14159265358979323846;
  for (int k = 0; k < 8; ++k)
    for (int i = 0; i < 16; ++i)
      g_matrix[k][i] = (float)cos((k + 0.5) * (i - 4) * pi / 8.0);
  g_matrix_ready = true;
}

class BitWriter {
 public:
  BitWriter(unsigned char* out, unsigned capacity)
      : out_(out), capacity_(capacity), bit_(0) {
    memset(out_, 0, capacity_);
  }
  void Put(unsigned value, unsigned bits) {
    while (bits--) {
      unsigned byte = bit_ >> 3;
      if (byte < capacity_ && ((value >> bits) & 1))
        out_[byte] |= (unsigned char)(0x80 >> (bit_ & 7));
      ++bit_;
    }
  }
  unsigned bytes() const { return (bit_ + 7) >> 3; }

 private:
  unsigned char* out_;
  unsigned capacity_;
  unsigned bit_;
};

// CRC-8, polynomial x^8 + x^4 + x^3 + x^2 + 1, initial value 0x0F, over a
// bit stream (Appendix B, frame header check).
class Crc8 {
 public:
  Crc8() : crc_(0x0F) {}
  void Put(unsigned value, unsigned bits) {
    while (bits--) {
      unsigned bit = (value >> bits) & 1;
      unsigned top = (crc_ >> 7) & 1;
      crc_ = (unsigned char)(crc_ << 1);
      if (top ^ bit) crc_ ^= 0x1D;
    }
  }
  unsigned char value() const { return crc_; }

 private:
  unsigned char crc_;
};

int ScaleFactor(float peak) {
  // Smallest s with peak < 2^(s + 1); 0..15.
  int s = 0;
  float limit = 2.0f;
  while (s < 15 && peak >= limit) {
    ++s;
    limit *= 2.0f;
  }
  return s;
}

}  // namespace

SbcEncoder::SbcEncoder() : blocks_(16), channels_(2), frame_length_(0) {
  memset(&config_, 0, sizeof(config_));
  Reset();
}

void SbcEncoder::Reset() {
  memset(history_, 0, sizeof(history_));
  memset(subband_, 0, sizeof(subband_));
}

bool SbcEncoder::Configure(const SbcConfig& c) {
  if (c.frequency > 3 || c.channel_mode > 3 || c.allocation > 1) return false;
  if (c.blocks != 4 && c.blocks != 8 && c.blocks != 12 && c.blocks != 16)
    return false;
  unsigned channels = c.channel_mode == kSbcMono ? 1 : 2;
  unsigned max_bitpool = (c.channel_mode == kSbcMono || c.channel_mode == kSbcDual)
      ? 16 * kSubbands : 32 * kSubbands;
  if (c.bitpool < 2 || c.bitpool > max_bitpool || c.bitpool > 250) return false;
  unsigned length = 4 + (4 * kSubbands * channels) / 8;
  if (c.channel_mode == kSbcMono || c.channel_mode == kSbcDual)
    length += (c.blocks * channels * c.bitpool + 7) / 8;
  else if (c.channel_mode == kSbcStereo)
    length += (c.blocks * c.bitpool + 7) / 8;
  else
    length += (kSubbands + c.blocks * c.bitpool + 7) / 8;
  if (length > kMaxFrameBytes) return false;
  BuildMatrix();
  config_ = c;
  blocks_ = c.blocks;
  channels_ = channels;
  frame_length_ = length;
  Reset();
  return true;
}

void SbcEncoder::Analyze(unsigned channel, const short* pcm, unsigned stride) {
  float* x = history_[channel];
  for (unsigned block = 0; block < blocks_; ++block) {
    // Shift in 8 new samples; the newest ends up at x[0].
    memmove(x + 8, x, 72 * sizeof(float));
    for (int i = 7; i >= 0; --i)
      x[i] = (float)pcm[(block * kSubbands + (7 - i)) * stride];
    float y[16];
    for (int i = 0; i < 16; ++i) {
      y[i] = kProto8[i] * x[i] + kProto8[i + 16] * x[i + 16] +
             kProto8[i + 32] * x[i + 32] + kProto8[i + 48] * x[i + 48] +
             kProto8[i + 64] * x[i + 64];
    }
    for (int k = 0; k < 8; ++k) {
      float s = 0;
      for (int i = 0; i < 16; ++i) s += g_matrix[k][i] * y[i];
      subband_[block][channel][k] = s;
    }
  }
}

void SbcEncoder::Allocate(const int scale[2][kSubbands],
                          int bits[2][kSubbands]) const {
  const unsigned m = kSubbands;
  int need[2][kSubbands];
  for (unsigned ch = 0; ch < channels_; ++ch) {
    for (unsigned sb = 0; sb < m; ++sb) {
      if (config_.allocation == kSbcSnr) {
        need[ch][sb] = scale[ch][sb];
      } else if (scale[ch][sb] == 0) {
        need[ch][sb] = -5;
      } else {
        int loudness = scale[ch][sb] - kOffset8[config_.frequency][sb];
        need[ch][sb] = loudness > 0 ? loudness / 2 : loudness;
      }
    }
  }
  // Mono and dual channel allocate per channel; stereo modes share the pool.
  const bool shared = config_.channel_mode == kSbcStereo ||
                      config_.channel_mode == kSbcJoint;
  unsigned groups = shared ? 1 : channels_;
  for (unsigned g = 0; g < groups; ++g) {
    unsigned first = shared ? 0 : g;
    unsigned last = shared ? channels_ : g + 1;
    const int pool = (int)config_.bitpool;
    int max_need = 0;
    for (unsigned ch = first; ch < last; ++ch)
      for (unsigned sb = 0; sb < m; ++sb)
        if (need[ch][sb] > max_need) max_need = need[ch][sb];
    int bitcount = 0, slicecount = 0, bitslice = max_need + 1;
    do {
      --bitslice;
      bitcount += slicecount;
      slicecount = 0;
      for (unsigned ch = first; ch < last; ++ch) {
        for (unsigned sb = 0; sb < m; ++sb) {
          int n = need[ch][sb];
          if (n > bitslice + 1 && n < bitslice + 16) ++slicecount;
          else if (n == bitslice + 1) slicecount += 2;
        }
      }
    } while (bitcount + slicecount < pool);
    if (bitcount + slicecount == pool) {
      bitcount += slicecount;
      --bitslice;
    }
    for (unsigned ch = first; ch < last; ++ch) {
      for (unsigned sb = 0; sb < m; ++sb) {
        int n = need[ch][sb];
        if (n < bitslice + 2) bits[ch][sb] = 0;
        else bits[ch][sb] = n - bitslice < 16 ? n - bitslice : 16;
      }
    }
    // Distribute the remainder, subband by subband, alternating channels.
    unsigned ch = first, sb = 0;
    while (bitcount < pool && sb < m) {
      if (bits[ch][sb] >= 2 && bits[ch][sb] < 16) {
        ++bits[ch][sb];
        ++bitcount;
      } else if (need[ch][sb] == bitslice + 1 && pool > bitcount + 1) {
        bits[ch][sb] = 2;
        bitcount += 2;
      }
      if (ch + 1 < last) ++ch;
      else { ch = first; ++sb; }
    }
    ch = first;
    sb = 0;
    while (bitcount < pool && sb < m) {
      if (bits[ch][sb] < 16) {
        ++bits[ch][sb];
        ++bitcount;
      }
      if (ch + 1 < last) ++ch;
      else { ch = first; ++sb; }
    }
  }
}

unsigned SbcEncoder::Encode(const short* pcm, unsigned char* out) {
  if (!frame_length_ || !pcm || !out) return 0;
  const unsigned m = kSubbands;
  for (unsigned ch = 0; ch < channels_; ++ch) Analyze(ch, pcm + ch, channels_);

  int scale[2][kSubbands];
  for (unsigned ch = 0; ch < channels_; ++ch) {
    for (unsigned sb = 0; sb < m; ++sb) {
      float peak = 0;
      for (unsigned b = 0; b < blocks_; ++b) {
        float v = fabsf(subband_[b][ch][sb]);
        if (v > peak) peak = v;
      }
      scale[ch][sb] = ScaleFactor(peak);
    }
  }
  unsigned join = 0;  // Bit (m - 1 - sb) set: subband sb is mid/side.
  if (config_.channel_mode == kSbcJoint) {
    for (unsigned sb = 0; sb + 1 < m; ++sb) {
      float peak_mid = 0, peak_side = 0;
      for (unsigned b = 0; b < blocks_; ++b) {
        float l = subband_[b][0][sb], r = subband_[b][1][sb];
        float mid = fabsf((l + r) * 0.5f), side = fabsf((l - r) * 0.5f);
        if (mid > peak_mid) peak_mid = mid;
        if (side > peak_side) peak_side = side;
      }
      int scale_mid = ScaleFactor(peak_mid), scale_side = ScaleFactor(peak_side);
      if (scale_mid + scale_side < scale[0][sb] + scale[1][sb]) {
        join |= 1u << (m - 1 - sb);
        scale[0][sb] = scale_mid;
        scale[1][sb] = scale_side;
        for (unsigned b = 0; b < blocks_; ++b) {
          float l = subband_[b][0][sb], r = subband_[b][1][sb];
          subband_[b][0][sb] = (l + r) * 0.5f;
          subband_[b][1][sb] = (l - r) * 0.5f;
        }
      }
    }
  }
  int bits[2][kSubbands];
  Allocate(scale, bits);

  BitWriter w(out, frame_length_);
  unsigned blocks_code = blocks_ / 4 - 1;
  unsigned header = (config_.frequency << 6) | (blocks_code << 4) |
                    (config_.channel_mode << 2) | (config_.allocation << 1) |
                    1;  // 8 subbands
  w.Put(0x9C, 8);
  w.Put(header, 8);
  w.Put(config_.bitpool, 8);
  w.Put(0, 8);  // CRC, filled in below.
  Crc8 crc;
  crc.Put(header, 8);
  crc.Put(config_.bitpool, 8);
  if (config_.channel_mode == kSbcJoint) {
    w.Put(join, m);
    crc.Put(join, m);
  }
  for (unsigned ch = 0; ch < channels_; ++ch) {
    for (unsigned sb = 0; sb < m; ++sb) {
      w.Put((unsigned)scale[ch][sb], 4);
      crc.Put((unsigned)scale[ch][sb], 4);
    }
  }
  out[3] = crc.value();
  for (unsigned b = 0; b < blocks_; ++b) {
    for (unsigned ch = 0; ch < channels_; ++ch) {
      for (unsigned sb = 0; sb < m; ++sb) {
        int nbits = bits[ch][sb];
        if (!nbits) continue;
        unsigned levels = (1u << nbits) - 1;
        float range = (float)(2 << scale[ch][sb]);  // 2^(scale + 1)
        float q = (subband_[b][ch][sb] / range + 1.0f) * (float)levels * 0.5f;
        unsigned value = q <= 0 ? 0 : (unsigned)q;
        if (value > levels) value = levels;
        w.Put(value, (unsigned)nbits);
      }
    }
  }
  return frame_length_;
}

}  // namespace bt

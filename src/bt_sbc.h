// SPDX-License-Identifier: GPL-3.0-or-later
// SBC encoder (Bluetooth A2DP specification, Appendix B "Technical
// Specification of SBC"). Written from the specification; no third-party
// codec code. Supports what A2DP sources need: 8 subbands, 4-16 blocks,
// mono/dual/stereo/joint stereo, loudness or SNR allocation.
#ifndef USB_AUDIO360_BT_SBC_H_
#define USB_AUDIO360_BT_SBC_H_

namespace bt {

enum SbcFrequency { kSbc16k = 0, kSbc32k = 1, kSbc44k1 = 2, kSbc48k = 3 };
enum SbcChannelMode { kSbcMono = 0, kSbcDual = 1, kSbcStereo = 2, kSbcJoint = 3 };
enum SbcAllocation { kSbcLoudness = 0, kSbcSnr = 1 };

struct SbcConfig {
  unsigned frequency;     // SbcFrequency
  unsigned blocks;        // 4, 8, 12 or 16
  unsigned channel_mode;  // SbcChannelMode
  unsigned allocation;    // SbcAllocation
  unsigned bitpool;       // 2..250 (A2DP sinks usually allow up to 53)
};

class SbcEncoder {
 public:
  static const unsigned kSubbands = 8;
  static const unsigned kMaxFrameBytes = 512;

  SbcEncoder();
  // Returns false for an unsupported or inconsistent configuration.
  bool Configure(const SbcConfig& config);
  void Reset();  // Clears the filter history (e.g. after a gap).
  unsigned channels() const { return channels_; }
  unsigned samples_per_frame() const { return blocks_ * kSubbands; }
  unsigned frame_length() const { return frame_length_; }
  // Encodes samples_per_frame() frames of 16-bit PCM (interleaved when
  // stereo) into one frame of frame_length() bytes. Returns its length.
  unsigned Encode(const short* pcm, unsigned char* out);

 private:
  void Analyze(unsigned channel, const short* pcm, unsigned stride);
  void Allocate(const int scale[2][kSubbands], int bits[2][kSubbands]) const;

  SbcConfig config_;
  unsigned blocks_;
  unsigned channels_;
  unsigned frame_length_;
  float history_[2][80];
  float subband_[16][2][kSubbands];  // [block][channel][subband]
};

}  // namespace bt

#endif  // USB_AUDIO360_BT_SBC_H_

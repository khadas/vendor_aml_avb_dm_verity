/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(AVB_INSIDE_LIBAVB_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb.h instead."
#endif

#ifndef AVB_VBMETA_IMAGE_H_
#define AVB_VBMETA_IMAGE_H_

#include "avb_sysdeps.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "avb_descriptor.h"

/* Size of the vbmeta image header. */
#define AVB_VBMETA_IMAGE_HEADER_SIZE 256

/* Magic for the vbmeta image header. */
#define AVB_MAGIC "AVB0"
#define AVB_MAGIC_LEN 4

/* Maximum size of the release string including the terminating NUL byte. */
#define AVB_RELEASE_STRING_SIZE 48

/* Flags for the vbmeta image.
 *
 * AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: If this flag is set,
 * hashtree image verification will be disabled.
 *
 * AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: If this flag is set,
 * verification will be disabled and descriptors will not be parsed.
 */
typedef enum {
  AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED = (1 << 0),
  AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED = (1 << 1)
} AvbVBMetaImageFlags;

/* Binary format for header of the vbmeta image.
 *
 * The vbmeta image consists of three blocks:
 *
 *  +-----------------------------------------+
 *  | Header data - fixed size                |
 *  +-----------------------------------------+
 *  | Authentication data - variable size     |
 *  +-----------------------------------------+
 *  | Auxiliary data - variable size          |
 *  +-----------------------------------------+
 *
 * The "Header data" block is described by this struct and is always
 * |AVB_VBMETA_IMAGE_HEADER_SIZE| bytes long.
 *
 * The "Authentication data" block is |authentication_data_block_size|
 * bytes long and contains the hash and signature used to authenticate
 * the vbmeta image. The type of the hash and signature is defined by
 * the |algorithm_type| field.
 *
 * The "Auxiliary data" is |auxiliary_data_block_size| bytes long and
 * contains the auxiliary data including the public key used to make
 * the signature and descriptors.
 *
 * The public key is at offset |public_key_offset| with size
 * |public_key_size| in this block. The size of the public key data is
 * defined by the |algorithm_type| field. The format of the public key
 * data is described in the |AvbRSAPublicKeyHeader| struct.
 *
 * The descriptors starts at |descriptors_offset| from the beginning
 * of the "Auxiliary Data" block and take up |descriptors_size|
 * bytes. Each descriptor is stored as a |AvbDescriptor| with tag and
 * number of bytes following. The number of descriptors can be
 * determined by walking this data until |descriptors_size| is
 * exhausted.
 *
 * The size of each of the "Authentication data" and "Auxiliary data"
 * blocks must be divisible by 64. This is to ensure proper alignment.
 *
 * Descriptors are free-form blocks stored in a part of the vbmeta
 * image subject to the same integrity checks as the rest of the
 * image. See the documentation for |AvbDescriptor| for well-known
 * descriptors. See avb_descriptor_foreach() for a convenience
 * function to iterate over descriptors.
 *
 * This struct is versioned, see the |required_libavb_version_major|
 * and |required_libavb_version_minor| fields. This represents the
 * minimum version of libavb required to verify the header and depends
 * on the features (e.g. algorithms, descriptors) used. Note that this
 * may be 1.0 even if generated by an avbtool from 1.4 but where no
 * features introduced after 1.0 has been used. See the "Versioning
 * and compatibility" section in the README.md file for more details.
 *
 * All fields are stored in network byte order when serialized. To
 * generate a copy with fields swapped to native byte order, use the
 * function avb_vbmeta_image_header_to_host_byte_order().
 *
 * Before reading and/or using any of this data, you MUST verify it
 * using avb_vbmeta_image_verify() and reject it unless it's signed by
 * a known good public key.
 */
typedef struct AvbVBMetaImageHeader {
  /*   0: Four bytes equal to "AVB0" (AVB_MAGIC). */
  uint8_t magic[AVB_MAGIC_LEN];

  /*   4: The major version of libavb required for this header. */
  uint32_t required_libavb_version_major;
  /*   8: The minor version of libavb required for this header. */
  uint32_t required_libavb_version_minor;

  /*  12: The size of the signature block. */
  uint64_t authentication_data_block_size;
  /*  20: The size of the auxiliary data block. */
  uint64_t auxiliary_data_block_size;

  /*  28: The verification algorithm used, see |AvbAlgorithmType| enum. */
  uint32_t algorithm_type;

  /*  32: Offset into the "Authentication data" block of hash data. */
  uint64_t hash_offset;
  /*  40: Length of the hash data. */
  uint64_t hash_size;

  /*  48: Offset into the "Authentication data" block of signature data. */
  uint64_t signature_offset;
  /*  56: Length of the signature data. */
  uint64_t signature_size;

  /*  64: Offset into the "Auxiliary data" block of public key data. */
  uint64_t public_key_offset;
  /*  72: Length of the public key data. */
  uint64_t public_key_size;

  /*  80: Offset into the "Auxiliary data" block of public key metadata. */
  uint64_t public_key_metadata_offset;
  /*  88: Length of the public key metadata. Must be set to zero if there
   *  is no public key metadata.
   */
  uint64_t public_key_metadata_size;

  /*  96: Offset into the "Auxiliary data" block of descriptor data. */
  uint64_t descriptors_offset;
  /* 104: Length of descriptor data. */
  uint64_t descriptors_size;

  /* 112: The rollback index which can be used to prevent rollback to
   *  older versions.
   */
  uint64_t rollback_index;

  /* 120: Flags from the AvbVBMetaImageFlags enumeration. This must be
   * set to zero if the vbmeta image is not a top-level image.
   */
  uint32_t flags;

  /* 124: The location of the rollback index defined in this header.
   * Only valid for the main vbmeta. For chained partitions, the rollback
   * index location must be specified in the AvbChainPartitionDescriptor
   * and this value must be set to 0.
   */
  uint32_t rollback_index_location;

  /* 128: The release string from avbtool, e.g. "avbtool 1.0.0" or
   * "avbtool 1.0.0 xyz_board Git-234abde89". Is guaranteed to be NUL
   * terminated. Applications must not make assumptions about how this
   * string is formatted.
   */
  uint8_t release_string[AVB_RELEASE_STRING_SIZE];

  /* 176: Padding to ensure struct is size AVB_VBMETA_IMAGE_HEADER_SIZE
   * bytes. This must be set to zeroes.
   */
  uint8_t reserved[80];
} AVB_ATTR_PACKED AvbVBMetaImageHeader;

/* Copies |src| to |dest|, byte-swapping fields in the process.
 *
 * Make sure you've verified |src| using avb_vbmeta_image_verify()
 * before accessing the data and/or using this function.
 */
void avb_vbmeta_image_header_to_host_byte_order(const AvbVBMetaImageHeader* src,
                                                AvbVBMetaImageHeader* dest);

/* Return codes used in avb_vbmeta_image_verify().
 *
 * AVB_VBMETA_VERIFY_RESULT_OK is returned if the vbmeta image header
 * is valid, the hash is correct and the signature is correct. Keep in
 * mind that you still need to check that you know the public key used
 * to sign the image, see avb_vbmeta_image_verify() for details.
 *
 * AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED is returned if the vbmeta
 * image header is valid but there is no signature or hash.
 *
 * AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER is returned if the
 * header of the vbmeta image is invalid, for example, invalid magic
 * or inconsistent data.
 *
 * AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION is returned if a) the
 * vbmeta image requires a minimum version of libavb which exceeds the
 * version of libavb used; or b) the vbmeta image major version
 * differs from the major version of libavb in use.
 *
 * AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH is returned if the hash
 * stored in the "Authentication data" block does not match the
 * calculated hash.
 *
 * AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH is returned if the
 * signature stored in the "Authentication data" block is invalid or
 * doesn't match the public key stored in the vbmeta image.
 */
typedef enum {
  AVB_VBMETA_VERIFY_RESULT_OK,
  AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED,
  AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER,
  AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION,
  AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH,
  AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH,
} AvbVBMetaVerifyResult;

/* Get a textual representation of |result|. */
const char* avb_vbmeta_verify_result_to_string(AvbVBMetaVerifyResult result);

/* Checks that vbmeta image at |data| of size |length| is a valid
 * vbmeta image. The complete contents of the vbmeta image must be
 * passed in. It's fine if |length| is bigger than the actual image,
 * typically callers of this function will load the entire contents of
 * the 'vbmeta_a' or 'vbmeta_b' partition and pass in its length (for
 * example, 1 MiB).
 *
 * See the |AvbVBMetaImageHeader| struct for information about the
 * three blocks (header, authentication, auxiliary) that make up a
 * vbmeta image.
 *
 * If the function returns |AVB_VBMETA_VERIFY_RESULT_OK| and
 * |out_public_key_data| is non-NULL, it will be set to point inside
 * |data| for where the serialized public key data is stored and
 * |out_public_key_length|, if non-NULL, will be set to the length of
 * the public key data. If there is no public key in the metadata then
 * |out_public_key_data| is set to NULL.
 *
 * See the |AvbVBMetaVerifyResult| enum for possible return values.
 *
 * VERY IMPORTANT:
 *
 *   1. Even if |AVB_VBMETA_VERIFY_RESULT_OK| is returned, you still
 *      need to check that the public key embedded in the image
 *      matches a known key! You can use 'avbtool extract_public_key'
 *      to extract the key (at build time, then store it along your
 *      code) and compare it to what is returned in
 *      |out_public_key_data|.
 *
 *   2. You need to check the |rollback_index| field against a stored
 *      value in NVRAM and reject the vbmeta image if the value in
 *      NVRAM is bigger than |rollback_index|. You must also update
 *      the value stored in NVRAM to the smallest value of
 *      |rollback_index| field from boot images in all bootable and
 *      authentic slots marked as GOOD.
 *
 * This is a low-level function to only verify the vbmeta data - you
 * are likely looking for avb_slot_verify() instead for verifying
 * integrity data for a whole set of partitions.
 */
AvbVBMetaVerifyResult avb_vbmeta_image_verify(
    const uint8_t* data,
    size_t length,
    const uint8_t** out_public_key_data,
    size_t* out_public_key_length) AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_VBMETA_IMAGE_H_ */

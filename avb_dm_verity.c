/*
 * Copyright (C) 2023 Amlogic, Inc. All rights reserved.
 *
 * All information contained herein is Amlogic confidential.
 *
 * This software is provided to you pursuant to Software License Agreement
 * (SLA) with Amlogic Inc ("Amlogic"). This software may be used
 * only in accordance with the terms of this agreement.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification is strictly prohibited without prior written permission from
 * Amlogic.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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

#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <libgen.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "libavb.h"

#define VBMETA_MAX_SIZE (64 * 1024)
#define AVB_PART_NAME_MAX_SIZE 32

typedef struct opt {
    const char *image;
    const char *partition_name;
    const char *active_slot;
    const char *output;
    char image_dir[128];
    char image_ext[8];
    bool file_mode;
} opt_t;

static void usage(void)
{
    fprintf(stderr, "\navb_dm_verity Help\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "Supported commands: print_partition_verity,\n");
    fprintf(stderr, "print_partition_verity:\n");
    fprintf(stderr, "\t--image <NAME>\tvbmeta image\n");
    fprintf(stderr, "\t--partition_name <NAME>\tpartition name\n");
    fprintf(stderr, "\t--active_slot <SLOT>\tactive slot, should be _a or _b\n");
    fprintf(stderr, "\t--file_mode read partition as files\n");
    fprintf(stderr, "\t--output <FILE>\toutput file\n");
    fprintf(stderr, "\t--help\t\tThis help information\n");
    fprintf(stderr, "\t--version\t\tPrint version\n");
}

static void parse_print_partition_verity(int argc, char *argv[], opt_t *opts)
{
    int32_t c = 0;

    memset(opts, 0, sizeof(*opts));

    while (1) {
        int opt_index = 0;
        static struct option options[] = {
            {"image", required_argument, 0, 'i'},
            {"partition_name", required_argument, 0, 'p'},
            {"active_slot", required_argument, 0, 'a'},
            {"output", required_argument, 0, 'o'},
            {"file_mode", no_argument, 0, 'f'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        c = getopt_long(argc, argv, "i:p:a:o:fh",
                options, &opt_index);
        if (-1 == c)
            break;
        switch (c) {
            case 'i':
                opts->image = optarg;
                break;
            case 'p':
                opts->partition_name = optarg;
                break;
            case 'a':
                opts->active_slot = optarg;
                break;
            case 'o':
                opts->output = optarg;
                break;
            case 'f':
                opts->file_mode = true;
                break;
            case 'h':
                usage();
                break;
            default:
                usage();
        }
    }
}

AvbIOResult get_prefix_suffix(const char *fullpath, char *dir, size_t dir_len,
        char *ext,  size_t ext_len)
{
    char *path = NULL;
    char *base = NULL;
    int32_t i = 0, len = 0;

    if (!fullpath || !dir || !ext)
        return AVB_IO_RESULT_ERROR_INVALID_ARGUMENT;

    path = strdup(fullpath);
    if (path) {
        memset(dir, 0, dir_len);
        strncpy(dir, dirname(path), dir_len - 1);
        free(path);
    } else {
        return AVB_IO_RESULT_ERROR_OOM;
    }
    path = strdup(fullpath);
    if (path) {
        memset(ext, 0, ext_len);
        base = basename(path);
        len = strlen(base);
        for (i = len - 1; i > 0; i--) {
            if (base[i] == '.')
                strncpy(ext, &base[i + 1], ext_len);
        }
        free(path);
    } else {
        return AVB_IO_RESULT_ERROR_OOM;
    }

    return AVB_IO_RESULT_OK;
}

AvbIOResult construct_fullname(opt_t *opts, const char *partition, char *fullname, size_t fullname_length)
{
    int32_t printed = 0;

    if (!partition || !fullname)
        return AVB_IO_RESULT_ERROR_INVALID_ARGUMENT;

    if (opts->file_mode) {
        printed = snprintf(fullname, fullname_length - 1, "%s/%s.%s",
                opts->image_dir, partition, opts->image_ext);
    } else {
        if (opts->active_slot && strlen(opts->active_slot)) {
            /* with active slot set */
            snprintf(fullname, fullname_length - 1, "/dev/%s%s",
                    partition, opts->active_slot);
        } else {
            snprintf(fullname, fullname_length - 1, "/dev/%s", partition);
        }
    }

    return AVB_IO_RESULT_OK;
}

AvbIOResult read_from_partition(opt_t *opts, const char *partition, int64_t offset,
        size_t num_bytes, void *buffer, size_t *out_num_read)
{
    FILE *fp = NULL;
    int32_t ret = 0;
    AvbIOResult result = AVB_IO_RESULT_ERROR_IO;

    if (!partition || !buffer || !out_num_read)
        return AVB_IO_RESULT_ERROR_IO;

    fp = fopen(partition, "rb");
    if (!fp) {
        avb_errorv(partition, "cannot open\n", NULL);
        return AVB_IO_RESULT_ERROR_IO;
    }
    if (offset < 0)
        ret = fseek(fp, offset, SEEK_END);
    else
        ret = fseek(fp, offset, SEEK_SET);
    if (ret) {
        avb_errorv(partition, "seeking to %d failed, errno = %d\n",
                offset, errno, NULL);
        goto out;
    }
    *out_num_read = fread(buffer, sizeof(uint8_t), num_bytes, fp);

    result = AVB_IO_RESULT_OK;

out:
    fclose(fp);

    return result;
}

static AvbIOResult load_vbmeta_from_partition_footer(opt_t *opts, const char *name,
        uint8_t **vbmeta_buf, size_t *vbmeta_size)
{
    uint8_t footer_buf[AVB_FOOTER_SIZE] = {0};
    size_t footer_num_read = 0;
    AvbFooter footer;
    AvbIOResult ret = AVB_IO_RESULT_ERROR_IO;
    AvbIOResult io_ret = AVB_IO_RESULT_ERROR_IO;
    size_t vbmeta_num_read = 0;
    uint64_t vbmeta_offset = 0;
    char fullname[PATH_MAX] = {0};

    if (!vbmeta_buf || !vbmeta_size)
        return AVB_IO_RESULT_ERROR_INVALID_ARGUMENT;

    avb_assert(footer_num_read == AVB_FOOTER_SIZE);

    io_ret = construct_fullname(opts, name, fullname, sizeof(fullname));
    if (io_ret != AVB_IO_RESULT_OK) {
        avb_errorv(name, ": failed to construct fullname.\n", NULL);
        goto out;
    }

    io_ret = read_from_partition(opts, fullname,
            -AVB_FOOTER_SIZE, AVB_FOOTER_SIZE,
            footer_buf, &footer_num_read);
    if (io_ret != AVB_IO_RESULT_OK) {
        avb_errorv(name, ": Error loading footer.\n", NULL);
        goto out;
    }

    if (!avb_footer_validate_and_byteswap((const AvbFooter*)footer_buf,
                &footer)) {
        avb_debugv(name, ": No footer detected.\n", NULL);
    } else {
        /* Basic footer sanity check since the data is untrusted. */
        if (footer.vbmeta_size > VBMETA_MAX_SIZE) {
            avb_errorv(
                    name, ": Invalid vbmeta size in footer.\n", NULL);
        } else {
            vbmeta_offset = footer.vbmeta_offset;
            *vbmeta_size = footer.vbmeta_size;
        }
    }

    *vbmeta_buf = avb_malloc(*vbmeta_size);
    if (*vbmeta_buf == NULL) {
        ret = AVB_IO_RESULT_ERROR_OOM;
        goto out;
    }

    if (vbmeta_offset != 0) {
        avb_debugv("Loading vbmeta struct in footer from partition '",
                name,
                "'.\n",
                NULL);
    } else {
        avb_debugv("Loading vbmeta struct from partition '",
                name,
                "'.\n",
                NULL);
    }

    io_ret = read_from_partition(opts, fullname,
            vbmeta_offset, *vbmeta_size, *vbmeta_buf, &vbmeta_num_read);
    if (io_ret != AVB_IO_RESULT_OK) {
        avb_errorv(name, ": Error loading vbmeta data.\n", NULL);
        goto out;
    }
    avb_assert(vbmeta_num_read <= *vbmeta_size);

    ret = AVB_IO_RESULT_OK;

out:
    return ret;

}

static AvbIOResult parse_hashtree_descriptor(opt_t *opts, AvbHashtreeDescriptor *desc,
        const uint8_t *name, const uint8_t *salt, const uint8_t *digest, bool *target_found)
{
    AvbIOResult ret = AVB_IO_RESULT_ERROR_IO;
    char part_name[AVB_PART_NAME_MAX_SIZE];
    size_t digest_len = 0;

    if (!avb_validate_utf8(name,
                desc->partition_name_len)) {
        avb_error("Partition name is not valid UTF-8.\n");
        ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
        goto out;
    }

    if (desc->partition_name_len >= AVB_PART_NAME_MAX_SIZE) {
        avb_error("Partition name does not fit.\n");
        ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
        goto out;
    }
    avb_memcpy(part_name, name, desc->partition_name_len);
    part_name[desc->partition_name_len] = '\0';

    if (!strcmp(part_name, opts->partition_name)) {
        FILE *fp = fopen(opts->output, "w");
        char *tmp_str = NULL;
        if (!fp) {
            avb_error("failed to open output file\n");
            goto out;
        }

        fprintf(fp, "DATA_BLOCKS=%"PRIu64"\n", desc->image_size / desc->data_block_size);
        fprintf(fp, "DATA_BLOCK_SIZE=%u\n", desc->data_block_size);
        fprintf(fp, "HASH_BLOCK_SIZE=%u\n", desc->hash_block_size);
        fprintf(fp, "HASH_ALGORITHM=%s\n", desc->hash_algorithm);
        tmp_str = avb_bin2hex(salt, desc->salt_len);
        if (!tmp_str) {
            fprintf(stderr, "failed to convert salt to hex\n");
            fclose(fp);
            goto out;
        }
        fprintf(fp, "SALT=%s\n", tmp_str);
        avb_free(tmp_str);
        tmp_str = avb_bin2hex(digest, desc->root_digest_len);
        if (!tmp_str) {
            avb_error("failed to convert root digest to hex\n");
            fclose(fp);
            goto out;
        }
        fprintf(fp, "ROOT_HASH=%s\n", tmp_str);
        avb_free(tmp_str);
        fprintf(fp, "DATA_SIZE=%"PRIu64"\n", desc->image_size);
        fclose(fp);
        *target_found = true;
    }

    ret = AVB_IO_RESULT_OK;

out:
    return ret;
}

static AvbIOResult parse_descriptors(opt_t *opts, const char *name, uint8_t *vbmeta_buf, size_t vbmeta_num_read)
{
    const AvbDescriptor** descriptors = NULL;
    size_t num_descriptors;
    size_t n;
    AvbIOResult ret = AVB_IO_RESULT_ERROR_IO;
    AvbIOResult sub_ret;

    descriptors =
        avb_descriptor_get_all(vbmeta_buf, vbmeta_num_read, &num_descriptors);
    for (n = 0; n < num_descriptors; n++) {
        AvbDescriptor desc;

        if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
            avb_errorv(name, ": Descriptor is invalid.\n", NULL);
            ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
            goto out;
        }

        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_HASH:
                /* do nothing */
                break;
            case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION:
                {
                    AvbChainPartitionDescriptor chain_desc;
                    const uint8_t *chain_partition_name;
                    uint8_t *chained_vbmeta_buf = NULL;
                    size_t vbmeta_size = 0;

                    if (!avb_chain_partition_descriptor_validate_and_byteswap(
                                (AvbChainPartitionDescriptor*)descriptors[n], &chain_desc)) {
                        avb_errorv(name,
                                ": Chain partition descriptor is invalid.\n",
                                NULL);
                        ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
                        goto out;
                    }

                    if (chain_desc.rollback_index_location == 0) {
                        avb_errorv(name,
                                ": Chain partition has invalid "
                                "rollback_index_location field.\n",
                                NULL);
                        ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
                        goto out;
                    }

                    chain_partition_name = ((const uint8_t *)descriptors[n]) +
                        sizeof(AvbChainPartitionDescriptor);

                    if (!strcmp(chain_partition_name, opts->partition_name)) {
                        sub_ret = load_vbmeta_from_partition_footer(opts,
                                chain_partition_name,
                                &chained_vbmeta_buf, &vbmeta_size);
                        if (sub_ret != AVB_IO_RESULT_OK) {
                            ret = sub_ret;
                            avb_free(chained_vbmeta_buf);
                            goto out;
                        } else {
                            ret = parse_descriptors(opts, chain_partition_name,
                                    chained_vbmeta_buf, vbmeta_size);
                            avb_free(chained_vbmeta_buf);
                            goto out;
                        }
                    }
                }
                break;
            case AVB_DESCRIPTOR_TAG_HASHTREE:
                {
                    AvbHashtreeDescriptor hashtree_desc;
                    bool target_found = false;
                    const uint8_t *hashtree_name = NULL;
                    const uint8_t *salt = NULL;
                    const uint8_t *digest = NULL;

                    hashtree_name = ((const uint8_t *)descriptors[n]) +
                            sizeof(AvbHashtreeDescriptor);
                    if (!avb_hashtree_descriptor_validate_and_byteswap(
                                (AvbHashtreeDescriptor *)descriptors[n], &hashtree_desc)) {
                        avb_errorv(
                                hashtree_name, ": Hashtree descriptor is invalid.\n", NULL);
                        ret = AVB_IO_RESULT_ERROR_INVALID_METADATA;
                        goto out;
                    }

                    salt = hashtree_name + hashtree_desc.partition_name_len;
                    digest = salt + hashtree_desc.salt_len;
                    sub_ret = parse_hashtree_descriptor(opts, &hashtree_desc,
                            hashtree_name, salt, digest, &target_found);
                    if (sub_ret != AVB_IO_RESULT_OK) {
                        avb_error("failed to parse hastree\n");
                        goto out;
                    }
                    if (target_found) {
                        ret = AVB_IO_RESULT_OK;
                        goto out;
                    }

                } break;
            case AVB_DESCRIPTOR_TAG_PROPERTY:
                /* Do nothing. */
                break;
        }
    }

    ret = AVB_IO_RESULT_OK;

out:
    return ret;
}

static AvbIOResult print_partition_verity(opt_t *opts)
{
    AvbIOResult ret = AVB_IO_RESULT_ERROR_INVALID_ARGUMENT;
    uint8_t *vbmeta_buf = NULL;
    size_t vbmeta_num_read = 0;

    if (opts->file_mode) {
        ret = get_prefix_suffix(opts->image, opts->image_dir, sizeof(opts->image_dir),
                opts->image_ext,  sizeof(opts->image_ext));
        if (ret != AVB_IO_RESULT_OK)
            return ret;
    }

    vbmeta_buf = avb_malloc(VBMETA_MAX_SIZE);
    if (!vbmeta_buf)
        return AVB_IO_RESULT_ERROR_OOM;

    ret = read_from_partition(opts, opts->image, 0,
            VBMETA_MAX_SIZE, vbmeta_buf, &vbmeta_num_read);
    if (ret != AVB_IO_RESULT_OK) {
        goto out;
    }

    ret = parse_descriptors(opts, "vbmeta", vbmeta_buf, vbmeta_num_read);

    ret = AVB_IO_RESULT_OK;

out:
    avb_free(vbmeta_buf);

    return ret;
}

int32_t main(int32_t argc, char *argv[])
{
    opt_t opts;
    int32_t ret = 0;

    if (argc <= 1) {
        usage();
        return 0;
    }

    if (!strcmp(argv[1], "print_partition_verity")) {
        parse_print_partition_verity(argc, argv, &opts);
        ret = print_partition_verity(&opts);
    } else {
        fprintf(stderr, "Unsupported cmd: %s\n", argv[0]);
        usage();
        ret = -ENOTSUP;
    }

    return ret;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mthcutil.c – tiny utility to inspect & edit MikroTik RouterBOOT
 *              hard_config blobs
 *
 * Copyright (c) 2025 Felix Kaechele <felix@kaechele.ca>
 *
 * AI Disclaimer: This code is largely LLM-generated
 *
 * Based on "Driver for MikroTik RouterBoot hard config"
 * https://git.openwrt.org/?p=openwrt/openwrt.git;a=blob;f=target/linux/generic/files/drivers/platform/mikrotik/rb_hardconfig.c;hb=2b0b16f1d1571b23425b2d7ab5dc3816e2ceec12
 * Copyright (C) 2020 Thibaut VARÈNE <hacks+kernel@slashdirt.org>
 *
 * Features
 * --------
 *  • list   – show all tag IDs, payload length, and interpreted values
 *  • get    – print the value of a single tag
 *  • set    – replace / add a tag payload (in‑place by default, or write
 *              to -o <file>)
 *
 * Unknown blocks and the WLAN calibration block (tag 0x16) are copied verbatim.
 *
 * Usage examples:
 *      ./mthcutil hard_config.bin list
 *      ./mthcutil hard_config.bin get 0x0b
 *      ./mthcutil hard_config.bin set 0x06 "7.18.2"
 *      ./mthcutil hard_config.bin set 0x15 0x01000000 --format u32 -o \
 *                  patched.bin
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALIGN 4
#define MAGIC 0x64726148u /* String "Hard" in little‑endian */

#define TAG_DEF(id, name) {RB_ID_##id, #name}

#define RB_ID_FLASH_INFO 0x03
#define RB_ID_MAC_ADDRESS_PACK 0x04
#define RB_ID_BOARD_PRODUCT_CODE 0x05
#define RB_ID_BIOS_VERSION 0x06
#define RB_ID_SDRAM_TIMINGS 0x08
#define RB_ID_DEVICE_TIMINGS 0x09
#define RB_ID_SOFTWARE_ID 0x0A
#define RB_ID_SERIAL_NUMBER 0x0B
#define RB_ID_MEMORY_SIZE 0x0D
#define RB_ID_MAC_ADDRESS_COUNT 0x0E
#define RB_ID_HW_OPTIONS 0x15
#define RB_ID_WLAN_DATA 0x16
#define RB_ID_BOARD_IDENTIFIER 0x17
#define RB_ID_PRODUCT_NAME 0x21
#define RB_ID_DEFCONF 0x26
#define RB_ID_BOARD_REVISION 0x27

struct tag_name {
  uint16_t id;
  const char *name;
};

static const struct tag_name tag_names[] = {
    TAG_DEF(FLASH_INFO, flash_info),
    TAG_DEF(MAC_ADDRESS_PACK, mac_address_pack),
    TAG_DEF(BOARD_PRODUCT_CODE, board_product_code),
    TAG_DEF(BIOS_VERSION, bios_version),
    TAG_DEF(SDRAM_TIMINGS, sdram_timings),
    TAG_DEF(DEVICE_TIMINGS, device_timings),
    TAG_DEF(SOFTWARE_ID, software_id),
    TAG_DEF(SERIAL_NUMBER, serial_number),
    TAG_DEF(MEMORY_SIZE, memory_size),
    TAG_DEF(MAC_ADDRESS_COUNT, mac_address_count),
    TAG_DEF(HW_OPTIONS, hw_options),
    TAG_DEF(WLAN_DATA, wlan_data),
    TAG_DEF(BOARD_IDENTIFIER, board_identifier),
    TAG_DEF(PRODUCT_NAME, product_name),
    TAG_DEF(DEFCONF, defconf),
    TAG_DEF(BOARD_REVISION, board_revision),
};

struct tag {
  uint16_t id;
  uint16_t plen;      /* padded length as stored in header */
  unsigned char *pay; /* malloc‑owned copy */
  size_t raw_len;     /* original payload length without padding */
};

struct tags_vec {
  struct tag *t;
  size_t n;
};

struct cli_args {
  const char *file;
  const char *cmd;
  uint16_t tag_id;
  const char *value;
  const char *format;
  const char *output;
  size_t pad_bytes;
  int verbose;
};

struct payload {
  unsigned char *data;
  size_t len;
  int needs_free;
};

static int verbose = 0;

/* ----------------------------- Utilities ----------------------------- */

static void die(const char *msg) {
  fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
  exit(EXIT_FAILURE);
}

static void log_verbose(const char *format, ...) {
  if (!verbose)
    return;

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

static size_t pad_len(size_t len) { return (ALIGN - (len % ALIGN)) % ALIGN; }

static const char *tag_name(uint16_t id) {
  for (size_t i = 0; i < sizeof(tag_names) / sizeof(tag_names[0]); ++i)
    if (tag_names[i].id == id)
      return tag_names[i].name;
  static char buf[16];
  snprintf(buf, sizeof(buf), "tag_0x%04x", id);
  return buf;
}

static void tags_free(struct tags_vec *v) {
  for (size_t i = 0; i < v->n; ++i)
    free(v->t[i].pay);
  free(v->t);
}

/* ----------------------------- File I/O ----------------------------- */

static size_t find_magic_in_file(FILE *f, size_t *file_size) {
  fseek(f, 0, SEEK_END);
  *file_size = ftell(f);
  rewind(f);

  if (*file_size < 4)
    return SIZE_MAX;

  uint32_t magic;
  size_t pos = 0;

  while (pos <= *file_size - 4) {
    fseek(f, pos, SEEK_SET);
    if (fread(&magic, 4, 1, f) == 1 && magic == MAGIC) {
      if (pos > 0) {
        log_verbose("Found hard_config at offset 0x%zx\n", pos);
      }
      return pos;
    }
    pos += 4; // Search on 4-byte boundaries for efficiency
  }
  return SIZE_MAX;
}

static size_t calculate_hardconfig_size(FILE *f, size_t magic_offset) {
  fseek(f, magic_offset + 4, SEEK_SET);
  size_t total_size = 4; /* magic header */
  unsigned char header[4];

  while (fread(header, 1, 4, f) == 4) {
    uint16_t id = *(uint16_t *)header;
    uint16_t plen = *(uint16_t *)(header + 2);

    if ((id == 0 && plen == 0) || (id == 0xFFFF && plen == 0xFFFF))
      break;

    total_size += 4 + plen;
    if (fseek(f, plen, SEEK_CUR) != 0)
      break;
  }
  return total_size;
}

static unsigned char *read_hardconfig_from_file(const char *path,
                                                size_t *len_out,
                                                size_t *offset_out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    die("open input");

  size_t file_size;
  size_t magic_offset = find_magic_in_file(f, &file_size);

  if (magic_offset == SIZE_MAX) {
    fclose(f);
    fprintf(stderr, "no hard_config block found in file\n");
    exit(EXIT_FAILURE);
  }

  size_t hardconfig_size = calculate_hardconfig_size(f, magic_offset);
  if (magic_offset + hardconfig_size > file_size) {
    hardconfig_size = file_size - magic_offset;
  }

  fseek(f, magic_offset, SEEK_SET);
  unsigned char *buf = malloc(hardconfig_size);
  if (!buf)
    die("malloc hardconfig");

  if (fread(buf, 1, hardconfig_size, f) != hardconfig_size)
    die("fread hardconfig");

  fclose(f);
  *len_out = hardconfig_size;
  *offset_out = magic_offset;
  return buf;
}

static void write_file(const char *path, const unsigned char *buf, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f)
    die("open output");
  if (fwrite(buf, 1, len, f) != len)
    die("fwrite");
  fclose(f);
}

/* ----------------------------- Parsing ----------------------------- */

static void parse(const unsigned char *buf, size_t len, struct tags_vec *out) {
  if (len < 4 || *(uint32_t *)buf != MAGIC) {
    fprintf(stderr, "invalid hard_config data\n");
    exit(EXIT_FAILURE);
  }

  size_t off = 4;
  struct tag *arr = NULL;
  size_t n = 0;

  while (off + 4 <= len) {
    uint16_t id = *(uint16_t *)(buf + off);
    uint16_t plen = *(uint16_t *)(buf + off + 2);
    if ((id == 0 && plen == 0) || (id == 0xFFFF && plen == 0xFFFF))
      break;
    if (off + 4 + plen > len) {
      fprintf(stderr, "corrupt TLV - past end\n");
      exit(EXIT_FAILURE);
    }

    size_t pay_len = plen - pad_len(plen);
    struct tag t = {id, plen, malloc(pay_len), pay_len};
    if (!t.pay)
      die("malloc tag payload");
    memcpy(t.pay, buf + off + 4, pay_len);

    arr = realloc(arr, (n + 1) * sizeof(*arr));
    if (!arr)
      die("realloc");
    arr[n++] = t;
    off += 4 + plen;
  }
  out->t = arr;
  out->n = n;
}

static unsigned char *rebuild_with_padding(struct tags_vec *v, size_t *out_len,
                                           size_t user_padding) {
  /* compute size */
  size_t len = 4; /* magic */
  for (size_t i = 0; i < v->n; ++i)
    len += 4 + v->t[i].plen;

  len += user_padding;

  unsigned char *buf = calloc(1, len);
  if (!buf)
    die("calloc rebuild");

  *(uint32_t *)buf = MAGIC;
  size_t off = 4;

  for (size_t i = 0; i < v->n; ++i) {
    const struct tag *t = &v->t[i];
    *(uint16_t *)(buf + off) = t->id;
    *(uint16_t *)(buf + off + 2) = t->plen;
    memcpy(buf + off + 4, t->pay, t->raw_len);
    off += 4 + t->plen;
  }

  /* user padding is already zeroed by calloc, set to 0xFF */
  if (user_padding > 0) {
    memset(buf + off, 0xFF, user_padding);
  }

  *out_len = len;
  return buf;
}

/* ----------------------------- Display ----------------------------- */

static void print_payload(const struct tag *t) {
  switch (t->id) {
  case RB_ID_BOARD_PRODUCT_CODE:
  case RB_ID_BIOS_VERSION:
  case RB_ID_SERIAL_NUMBER:
  case RB_ID_BOARD_IDENTIFIER:
  case RB_ID_PRODUCT_NAME:
  case RB_ID_DEFCONF:
  case RB_ID_BOARD_REVISION:
    printf("%.*s", (int)t->raw_len, (char *)t->pay);
    break;

  case RB_ID_FLASH_INFO:
  case RB_ID_SDRAM_TIMINGS:
  case RB_ID_DEVICE_TIMINGS:
  case RB_ID_SOFTWARE_ID:
  case RB_ID_MEMORY_SIZE:
  case RB_ID_HW_OPTIONS:
    for (size_t i = 0; i + 4 <= t->raw_len; i += 4) {
      uint32_t val = *(uint32_t *)(t->pay + i);
      printf("0x%X%s", val, (i + 4 < t->raw_len) ? ", " : "");
    }
    break;

  case RB_ID_MAC_ADDRESS_PACK:
    if (t->raw_len >= 6) {
      printf("%02X", t->pay[0]);
      for (size_t i = 1; i < 6; i++) {
        printf(":%02X", t->pay[i]);
      }
    }
    break;

  case RB_ID_MAC_ADDRESS_COUNT:
    if (t->raw_len >= 4) {
      uint32_t count = *(uint32_t *)t->pay;
      printf("%u", count);
    }
    break;

  default:
    for (size_t i = 0; i < t->raw_len; ++i)
      printf("%02X", t->pay[i]);
  }
}

/* ----------------------------- Payload Parsing -----------------------------
 */

static unsigned char *parse_hex(const char *s, size_t *out_len) {
  size_t len = strlen(s);
  if (len % 2) {
    fprintf(stderr, "hex value must have even length\n");
    exit(EXIT_FAILURE);
  }

  unsigned char *buf = malloc(len / 2);
  if (!buf)
    die("malloc hex");

  for (size_t i = 0; i < len; i += 2) {
    if (!isxdigit((unsigned char)s[i]) || !isxdigit((unsigned char)s[i + 1])) {
      fprintf(stderr, "invalid hex\n");
      exit(EXIT_FAILURE);
    }
    buf[i / 2] = (unsigned char)strtol((char[]){s[i], s[i + 1], 0}, NULL, 16);
  }
  *out_len = len / 2;
  return buf;
}

static struct payload parse_payload(const char *value, const char *format) {
  struct payload p = {0};

  if (strcmp(format, "str") == 0) {
    p.len = strlen(value) + 1;
    p.data = (unsigned char *)value;
    p.needs_free = 0;
  } else if (strcmp(format, "hex") == 0) {
    p.data = parse_hex(value, &p.len);
    p.needs_free = 1;
  } else if (strcmp(format, "u32") == 0) {
    uint32_t val = (uint32_t)strtoul(value, NULL, 0);
    p.len = 4;
    p.data = malloc(4);
    if (!p.data)
      die("malloc u32");
    *(uint32_t *)p.data = val;
    p.needs_free = 1;
  } else {
    fprintf(stderr, "unknown format: %s\n", format);
    exit(EXIT_FAILURE);
  }
  return p;
}

static void set_tag(struct tags_vec *v, uint16_t id, const unsigned char *data,
                    size_t len) {
  size_t pad = pad_len(len);
  size_t plen = len + pad;

  for (size_t i = 0; i < v->n; ++i) {
    if (v->t[i].id == id) {
      free(v->t[i].pay);
      v->t[i].pay = malloc(len);
      if (!v->t[i].pay)
        die("malloc set");
      memcpy(v->t[i].pay, data, len);
      v->t[i].raw_len = len;
      v->t[i].plen = (uint16_t)plen;
      return;
    }
  }

  /* append new tag */
  v->t = realloc(v->t, (v->n + 1) * sizeof(*v->t));
  if (!v->t)
    die("realloc append");
  v->t[v->n] = (struct tag){id, (uint16_t)plen, malloc(len), len};
  if (!v->t[v->n].pay)
    die("malloc append pay");
  memcpy(v->t[v->n].pay, data, len);
  v->n++;
}

/* ----------------------------- Output Writing ----------------------------- */

static void write_output(const struct cli_args *args, unsigned char *buf,
                         size_t len, size_t original_len, size_t offset) {
  if (strcmp(args->output, args->file) == 0) {
    // In-place modification - pad to original size if needed
    if (len < original_len) {
      printf("Padding from %zu to %zu bytes for in-place patch\n", len,
             original_len);
      buf = realloc(buf, original_len);
      if (!buf)
        die("realloc inplace padding");
      memset(buf + len, 0xFF, original_len - len);
      len = original_len;
    }

    FILE *f = fopen(args->file, "r+b");
    if (!f)
      die("open for update");
    if (fseek(f, offset, SEEK_SET) != 0)
      die("seek for update");
    if (fwrite(buf, 1, len, f) != len)
      die("write update");
    fclose(f);
    printf("Patched %s in hard_config at offset 0x%zx (%zu bytes)\n",
           args->file, offset, len);
  } else {
    write_file(args->output, buf, len);
    printf("Wrote %s (%zu bytes)\n", args->output, len);
  }
}

/* ----------------------------- Command Handlers -----------------------------
 */

static int cmd_list(const struct cli_args *args, struct tags_vec *tags) {
  for (size_t i = 0; i < tags->n; ++i) {
    const struct tag *t = &tags->t[i];
    printf("0x%04x\t%-20s\t%4zu B\t", t->id, tag_name(t->id), t->raw_len);
    if (args->verbose)
      printf("(padded: %u B) ", t->plen);
    print_payload(t);
    putchar('\n');
  }
  return 0;
}

static int cmd_get(const struct cli_args *args, struct tags_vec *tags) {
  for (size_t i = 0; i < tags->n; ++i) {
    if (tags->t[i].id == args->tag_id) {
      log_verbose("Found tag 0x%04x, raw: %zu bytes, padded: %u bytes\n",
                  args->tag_id, tags->t[i].raw_len, tags->t[i].plen);
      log_verbose("Value: ");
      print_payload(&tags->t[i]);
      putchar('\n');
      return 0;
    }
  }
  fprintf(stderr, "tag not found\n");
  return 1;
}

static int cmd_set(const struct cli_args *args, struct tags_vec *tags,
                   size_t original_len, size_t offset) {
  struct payload p = parse_payload(args->value, args->format);

  printf("Setting tag 0x%04x (%s) to: %s\n", args->tag_id,
         tag_name(args->tag_id), args->value);
  log_verbose("Format: %s, payload: %zu bytes\n", args->format, p.len);

  set_tag(tags, args->tag_id, p.data, p.len);

  size_t out_len;
  unsigned char *buf = rebuild_with_padding(tags, &out_len, args->pad_bytes);

  if (args->pad_bytes > 0) {
    log_verbose("Added %zu bytes of padding\n", args->pad_bytes);
  }

  write_output(args, buf, out_len, original_len, offset);

  free(buf);
  if (p.needs_free)
    free(p.data);
  return 0;
}

/* ----------------------------- CLI ----------------------------- */

static const struct {
  const char *name;
  int needs_tag_id;
  int needs_value;
} commands[] = {
    {"list", 0, 0},
    {"get", 1, 0},
    {"set", 1, 1},
};

static void usage(const char *prog) {
  fprintf(stderr,
          "MikroTik hard_config utility\n"
          "Copyright (c) 2025 Felix Kaechele <felix@kaechele.ca>\n"
          "\n"
          "Usage:\n"
          "  %s <file> list [-v]\n"
          "  %s <file> get <tag> [-v]\n"
          "  %s <file> set <tag> <value> [--format str|hex|u32] [--pad "
          "<bytes>] [-o outfile] [-v]\n"
          "\n"
          "Options:\n"
          "  --format str|hex|u32  Input format (default: str)\n"
          "  --pad <bytes>         Add specified number of 0xFF bytes\n"
          "  -o <outfile>          Write hard_config segment to file instead "
          "of in-place patch\n"
          "  -v                    Enable verbose output\n",
          prog, prog, prog);
  exit(EXIT_FAILURE);
}

static struct cli_args parse_args(int argc, char *argv[]) {
  struct cli_args args = {
      .format = "str", .output = NULL, .pad_bytes = 0, .verbose = 0};

  if (argc < 3)
    usage(argv[0]);

  args.file = argv[1];
  args.cmd = argv[2];

  // Find command info
  int cmd_idx = -1;
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
    if (strcmp(args.cmd, commands[i].name) == 0) {
      cmd_idx = (int)i;
      break;
    }
  }
  if (cmd_idx == -1)
    usage(argv[0]);

  int arg_idx = 3;

  // Parse required args
  if (commands[cmd_idx].needs_tag_id) {
    if (arg_idx >= argc)
      usage(argv[0]);
    args.tag_id = (uint16_t)strtoul(argv[arg_idx++], NULL, 0);
  }

  if (commands[cmd_idx].needs_value) {
    if (arg_idx >= argc)
      usage(argv[0]);
    args.value = argv[arg_idx++];
  }

  // Parse optional args
  while (arg_idx < argc) {
    if (strcmp(argv[arg_idx], "-v") == 0) {
      args.verbose = 1;
    } else if (strcmp(argv[arg_idx], "--format") == 0 && arg_idx + 1 < argc) {
      args.format = argv[++arg_idx];
    } else if (strcmp(argv[arg_idx], "--pad") == 0 && arg_idx + 1 < argc) {
      args.pad_bytes = (size_t)strtoul(argv[++arg_idx], NULL, 0);
    } else if (strcmp(argv[arg_idx], "-o") == 0 && arg_idx + 1 < argc) {
      args.output = argv[++arg_idx];
    } else {
      usage(argv[0]);
    }
    arg_idx++;
  }

  if (!args.output)
    args.output = args.file; // Default to in-place
  return args;
}

/* ----------------------------- Main ----------------------------- */

int main(int argc, char *argv[]) {
  struct cli_args args = parse_args(argc, argv);
  verbose = args.verbose;

  // Load and parse hard_config
  size_t len, offset;
  unsigned char *buf = read_hardconfig_from_file(args.file, &len, &offset);

  log_verbose("hard_config: offset 0x%zx, size %zu bytes\n", offset, len);

  struct tags_vec tags = {0};
  parse(buf, len, &tags);
  free(buf);

  log_verbose("Parsed %zu tags\n", tags.n);

  // Execute command
  int result = 1;
  if (strcmp(args.cmd, "list") == 0) {
    result = cmd_list(&args, &tags);
  } else if (strcmp(args.cmd, "get") == 0) {
    result = cmd_get(&args, &tags);
  } else if (strcmp(args.cmd, "set") == 0) {
    result = cmd_set(&args, &tags, len, offset);
  } else {
    usage(argv[0]);
  }

  tags_free(&tags);
  return result;
}
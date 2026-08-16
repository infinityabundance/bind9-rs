#ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 200809L
#endif

/* probe-maxminddb.c — libmaxminddb 1.13.3 surface probe (§33, §37).
 *
 * Exercises the full conservation surface against the pinned upstream test
 * databases: version/strerror, open-error taxonomy, metadata dump (in the
 * mmdblookup -v format), metadata entry-data-list dump, search-tree walk
 * (MMDB_read_node + bounds), deterministic address lookups with path
 * lookups and full entry dumps, the decoder database (all data types),
 * corrupt databases (broken pointers/search tree, deep nesting, oversized
 * containers), the IPv6-in-IPv4 error, and getaddrinfo error codes.
 *
 * The Rust mirror (maxminddb-probe.rs) must produce byte-identical stdout.
 *
 * Usage: probe-maxminddb <test-data-dir>
 */
#include <maxminddb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

static const char *typname(uint32_t t) {
    switch (t) {
        case MMDB_DATA_TYPE_EXTENDED: return "extended";
        case MMDB_DATA_TYPE_POINTER: return "pointer";
        case MMDB_DATA_TYPE_UTF8_STRING: return "utf8_string";
        case MMDB_DATA_TYPE_DOUBLE: return "double";
        case MMDB_DATA_TYPE_BYTES: return "bytes";
        case MMDB_DATA_TYPE_UINT16: return "uint16";
        case MMDB_DATA_TYPE_UINT32: return "uint32";
        case MMDB_DATA_TYPE_MAP: return "map";
        case MMDB_DATA_TYPE_INT32: return "int32";
        case MMDB_DATA_TYPE_UINT64: return "uint64";
        case MMDB_DATA_TYPE_UINT128: return "uint128";
        case MMDB_DATA_TYPE_ARRAY: return "array";
        case MMDB_DATA_TYPE_CONTAINER: return "container";
        case MMDB_DATA_TYPE_END_MARKER: return "end_marker";
        case MMDB_DATA_TYPE_BOOLEAN: return "boolean";
        case MMDB_DATA_TYPE_FLOAT: return "float";
        default: return "unknown";
    }
}

/* Render one entry data value the same way in the Rust mirror. */
static void render_value(FILE *f, MMDB_entry_data_s *d) {
    switch (d->type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
            fprintf(f, "\"%.*s\"", (int)d->data_size, d->utf8_string);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            fprintf(f, "%f", d->double_value);
            break;
        case MMDB_DATA_TYPE_BYTES: {
            for (uint32_t i = 0; i < d->data_size; i++) {
                fprintf(f, "%02X", d->bytes[i]);
            }
        } break;
        case MMDB_DATA_TYPE_UINT16: fprintf(f, "%u", d->uint16); break;
        case MMDB_DATA_TYPE_UINT32: fprintf(f, "%u", d->uint32); break;
        case MMDB_DATA_TYPE_INT32: fprintf(f, "%d", d->int32); break;
        case MMDB_DATA_TYPE_UINT64: fprintf(f, "%llu", (unsigned long long)d->uint64); break;
        case MMDB_DATA_TYPE_UINT128:
            fprintf(f, "%llu", (unsigned long long)d->uint128);
            break;
        case MMDB_DATA_TYPE_BOOLEAN: fprintf(f, "%s", d->boolean ? "true" : "false"); break;
        case MMDB_DATA_TYPE_FLOAT: fprintf(f, "%f", d->float_value); break;
        default: break;
    }
}

/* data_size is only defined for strings, bytes, map/array headers, boolean
 * and pointers (maxminddb.h).  For the numeric types the C's
 * lookup_path_in_map leaves it as uninitialized stack residue, so both
 * probes render "-" for those. */
static void render_data_size(FILE *f, MMDB_entry_data_s *d) {
    switch (d->type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        case MMDB_DATA_TYPE_BYTES:
        case MMDB_DATA_TYPE_MAP:
        case MMDB_DATA_TYPE_ARRAY:
        case MMDB_DATA_TYPE_BOOLEAN:
        case MMDB_DATA_TYPE_POINTER:
            fprintf(f, "data_size=%u ", d->data_size);
            break;
        default:
            fprintf(f, "data_size=- ");
            break;
    }
}

static void render_entry(FILE *f, MMDB_entry_data_s *d) {
    fprintf(f, "type=%s has_data=%d ",
            typname(d->type), d->has_data ? 1 : 0);
    render_data_size(f, d);
    fprintf(f, "off=%u next=%u val=", d->offset, d->offset_to_next);
    render_value(f, d);
    fprintf(f, "\n");
}

/* mmdblookup -v metadata format */
static void dump_meta(MMDB_s *mmdb) {
    char date[40];
    const time_t epoch = (const time_t)mmdb->metadata.build_epoch;
    struct tm *tm = gmtime(&epoch);
    if (tm != NULL) {
        strftime(date, sizeof(date), "%F %T UTC", tm);
    } else {
        snprintf(date, sizeof(date), "out of range");
    }
    fprintf(stdout,
            "  Database metadata\n"
            "    Node count:    %u\n"
            "    Record size:   %u bits\n"
            "    IP version:    IPv%u\n"
            "    Binary format: %u.%u\n"
            "    Build epoch:   %llu (%s)\n"
            "    Type:          %s\n"
            "    Languages:     ",
            mmdb->metadata.node_count, mmdb->metadata.record_size,
            mmdb->metadata.ip_version,
            mmdb->metadata.binary_format_major_version,
            mmdb->metadata.binary_format_minor_version,
            (unsigned long long)mmdb->metadata.build_epoch, date,
            mmdb->metadata.database_type);
    for (size_t i = 0; i < mmdb->metadata.languages.count; i++) {
        fprintf(stdout, "%s", mmdb->metadata.languages.names[i]);
        if (i < mmdb->metadata.languages.count - 1) {
            fprintf(stdout, " ");
        }
    }
    fprintf(stdout, "\n    Description:\n");
    for (size_t i = 0; i < mmdb->metadata.description.count; i++) {
        fprintf(stdout, "      %s:   %s\n",
                mmdb->metadata.description.descriptions[i]->language,
                mmdb->metadata.description.descriptions[i]->description);
    }
    fprintf(stdout, "\n");
}

static char *join(const char *dir, const char *name) {
    size_t n = strlen(dir) + strlen(name) + 2;
    char *p = malloc(n);
    snprintf(p, n, "%s/%s", dir, name);
    return p;
}

static void lookup_one(MMDB_s *mmdb, const char *ip) {
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s r = MMDB_lookup_string(mmdb, ip, &gai_error, &mmdb_error);
    fprintf(stdout, "  lookup %s: found=%d netmask=%u gai=%d mmdb_err=%d\n",
            ip, r.found_entry ? 1 : 0, r.netmask, gai_error, mmdb_error);
    if (!r.found_entry) {
        return;
    }
    /* path lookups */
    const char *paths[][5] = {
        {"city", "names", "en", NULL, NULL}, {"country", "names", "en", NULL, NULL},
        {"subdivisions", "0", "names", "en", NULL}, {"location", "latitude", NULL, NULL, NULL},
        {"location", "longitude", NULL, NULL, NULL}, {"location", "accuracy_radius", NULL, NULL, NULL},
        {"traits", "network", NULL, NULL, NULL}, {"postal", "code", NULL, NULL, NULL},
        {"registered_country", "iso_code", NULL, NULL, NULL},
        {"nope", NULL, NULL, NULL, NULL}, {"city", "nope", NULL, NULL, NULL},
        {"subdivisions", "-1", "names", "en", NULL}, {"subdivisions", "9", NULL, NULL, NULL},
        {"subdivisions", "x", NULL, NULL, NULL},
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        MMDB_entry_data_s d;
        memset(&d, 0, sizeof(d));
        int status = MMDB_aget_value(&r.entry, &d, paths[i]);
        if (status != MMDB_SUCCESS) {
            fprintf(stdout, "    path");
            for (int j = 0; paths[i][j] != NULL; j++) {
                fprintf(stdout, " %s", paths[i][j]);
            }
            fprintf(stdout, ": status=%d %s\n", status, MMDB_strerror(status));
        } else {
            fprintf(stdout, "    path");
            for (int j = 0; paths[i][j] != NULL; j++) {
                fprintf(stdout, " %s", paths[i][j]);
            }
            fprintf(stdout, ": ");
            render_entry(stdout, &d);
        }
    }
    /* full entry data list dump */
    MMDB_entry_data_list_s *list = NULL;
    int status = MMDB_get_entry_data_list(&r.entry, &list);
    if (status != MMDB_SUCCESS) {
        fprintf(stdout, "    get_entry_data_list: %d %s\n", status, MMDB_strerror(status));
        return;
    }
    fprintf(stdout, "    dump:\n");
    int dstatus = MMDB_dump_entry_data_list(stdout, list, 0);
    fprintf(stdout, "    dump_status=%d\n", dstatus);
    MMDB_free_entry_data_list(list);
}

static void decoder_fields(MMDB_s *mmdb, const char *ip) {
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s r = MMDB_lookup_string(mmdb, ip, &gai_error, &mmdb_error);
    fprintf(stdout, "  decoder %s: found=%d netmask=%u gai=%d mmdb_err=%d\n",
            ip, r.found_entry ? 1 : 0, r.netmask, gai_error, mmdb_error);
    if (!r.found_entry) {
        return;
    }
    const char *fields[] = {"utf8_string", "double", "bytes", "uint16", "uint32",
                            "map", "int32", "uint64", "uint128", "array",
                            "boolean", "float", NULL};
    for (int i = 0; fields[i] != NULL; i++) {
        MMDB_entry_data_s d;
        memset(&d, 0, sizeof(d));
        const char *path[] = {fields[i], NULL};
        int status = MMDB_aget_value(&r.entry, &d, path);
        if (status != MMDB_SUCCESS) {
            fprintf(stdout, "    %s: status=%d\n", fields[i], status);
        } else {
            fprintf(stdout, "    %s: ", fields[i]);
            render_entry(stdout, &d);
        }
    }
    MMDB_entry_data_list_s *list = NULL;
    int status = MMDB_get_entry_data_list(&r.entry, &list);
    fprintf(stdout, "    list_status=%d\n", status);
    if (status == MMDB_SUCCESS) {
        fprintf(stdout, "    dump:\n");
        int dstatus = MMDB_dump_entry_data_list(stdout, list, 0);
        fprintf(stdout, "    dump_status=%d\n", dstatus);
        MMDB_free_entry_data_list(list);
    }
}

static void write_file_bytes(const char *path, const unsigned char *bytes, size_t n) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        if (n > 0) {
            ssize_t w = write(fd, bytes, n);
            (void)w;
        }
        close(fd);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <test-data-dir>\n", argv[0]);
        return 2;
    }
    const char *tdir = argv[1];

    printf("== version ==\n%s\n", MMDB_lib_version());

    printf("== strerror ==\n");
    for (int c = 0; c <= 11; c++) {
        printf("%d: %s\n", c, MMDB_strerror(c));
    }
    printf("999: %s\n", MMDB_strerror(999));

    /* open-error taxonomy (deterministic temp files) */
    write_file_bytes("/tmp/mmdb-empty", (const unsigned char *)"", 0);
    write_file_bytes("/tmp/mmdb-garbage",
                     (const unsigned char *)"this is not a maxmind db file at all", 38);
    {
        /* truncated: first 500 bytes of the city test db */
        char *city = join(tdir, "GeoIP2-City-Test.mmdb");
        FILE *in = fopen(city, "rb");
        unsigned char buf[500];
        size_t got = in ? fread(buf, 1, sizeof(buf), in) : 0;
        if (in) {
            fclose(in);
        }
        write_file_bytes("/tmp/mmdb-trunc", buf, got);
        free(city);
    }
    printf("== open errors ==\n");
    const char *badfiles[] = {"/tmp/mmdb-nonexistent", "/tmp/mmdb-empty",
                              "/tmp/mmdb-garbage", "/tmp/mmdb-trunc", NULL};
    for (int i = 0; badfiles[i] != NULL; i++) {
        MMDB_s m;
        memset(&m, 0, sizeof(m));
        int status = MMDB_open(badfiles[i], MMDB_MODE_MMAP, &m);
        printf("%s: %d %s\n", badfiles[i], status, MMDB_strerror(status));
        if (status == MMDB_SUCCESS) {
            MMDB_close(&m);
        }
    }

    /* ---- GeoIP2-City-Test.mmdb ---- */
    {
        char *db = join(tdir, "GeoIP2-City-Test.mmdb");
        MMDB_s mmdb;
        int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
        printf("== open GeoIP2-City-Test.mmdb ==\n%d %s\n", status, MMDB_strerror(status));
        free(db);
        if (status != MMDB_SUCCESS) {
            return 1;
        }

        printf("== metadata ==\n");
        dump_meta(&mmdb);
        MMDB_entry_data_list_s *mlist = NULL;
        int mstatus = MMDB_get_metadata_as_entry_data_list(&mmdb, &mlist);
        printf("== metadata list ==\nstatus=%d\n", mstatus);
        if (mstatus == MMDB_SUCCESS) {
            int dstatus = MMDB_dump_entry_data_list(stdout, mlist, 0);
            printf("dump_status=%d\n", dstatus);
            MMDB_free_entry_data_list(mlist);
        }

        printf("== read_node ==\n");
        for (uint32_t n = 0; n < 3; n++) {
            MMDB_search_node_s node;
            int s = MMDB_read_node(&mmdb, n, &node);
            printf("node %u: status=%d left=%llu lt=%u le=%u right=%llu rt=%u re=%u\n",
                   n, s, (unsigned long long)node.left_record,
                   node.left_record_type, node.left_record_entry.offset,
                   (unsigned long long)node.right_record,
                   node.right_record_type, node.right_record_entry.offset);
        }
        {
            MMDB_search_node_s node;
            int s = MMDB_read_node(&mmdb, mmdb.metadata.node_count, &node);
            printf("node==count: status=%d\n", s);
        }

        printf("== lookups ==\n");
        const char *ips[] = {"81.2.69.142", "81.2.69.143", "81.2.69.144",
                             "2001:218::1", "2001:218::", "2a00:1450:4001:815::200e",
                             "::ffff:81.2.69.142", "0.0.0.0", "255.255.255.255",
                             "e900::", "10.0.0.1", NULL};
        for (int i = 0; ips[i] != NULL; i++) {
            lookup_one(&mmdb, ips[i]);
        }

        printf("== gai errors ==\n");
        const char *bads[] = {"not an ip", "", "1.2.3", "1.2.3.4.5",
                              "256.1.1.1", "01.2.3.4", "1.2.3.x",
                              "0x7f.1", "1.2.3.4.5.6", "010.0.0.1",
                              "0x7f.0.0.1", "1.2.3.4 ", "1.2.3.4. ",
                              "09.0.0.1", "0x.1", "1..2", ".1.2.3",
                              "1.2.3.", "4294967295", "4294967296",
                              "1.2.3.256", "0xffffffff", "0x100000000",
                              "1.2.3.4 xyz", "1.2.3.4\t", " 1.2.3.4",
                              "+1.2.3.4", "0x1f.0x1", "0377.0.0.1",
                              "1:2:3:4:5:6:7", "1::2::3", "::ffff:1.2.3.256",
                              "1:2:3:4:5:6:7:8:9", "fe80::1%", "fe80::1%eth0",
                              "fe80::1%nonexistentzz", "fe80::1%3", "fe80::1%0",
                              "fe80::1%99999999999999999999", "1.2.3.4%eth0",
                              "%", NULL};
        for (int i = 0; bads[i] != NULL; i++) {
            int gai_error = 0, mmdb_error = 0;
            MMDB_lookup_string(&mmdb, bads[i], &gai_error, &mmdb_error);
            /* also resolve the address directly so both probes can print
             * the exact bytes glibc chose (inet_aton fallback forms) */
            char addrstr[INET6_ADDRSTRLEN] = "-";
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_flags = AI_NUMERICHOST;
            hints.ai_socktype = SOCK_STREAM;
            struct addrinfo *res = NULL;
            int gai2 = getaddrinfo(bads[i], NULL, &hints, &res);
            if (gai2 == 0 && res != NULL && res->ai_addr != NULL) {
                if (res->ai_addr->sa_family == AF_INET) {
                    inet_ntop(AF_INET,
                              &((struct sockaddr_in *)res->ai_addr)->sin_addr,
                              addrstr, sizeof(addrstr));
                } else if (res->ai_addr->sa_family == AF_INET6) {
                    inet_ntop(AF_INET6,
                              &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
                              addrstr, sizeof(addrstr));
                }
                freeaddrinfo(res);
            }
            printf("  %s -> gai=%d mmdb_err=%d addr=%s\n", bads[i], gai_error,
                   mmdb_error, addrstr);
        }
        MMDB_close(&mmdb);
    }

    /* ---- decoder db ---- */
    {
        char *db = join(tdir, "MaxMind-DB-test-decoder.mmdb");
        MMDB_s mmdb;
        int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
        printf("== open MaxMind-DB-test-decoder.mmdb ==\n%d %s\n", status, MMDB_strerror(status));
        free(db);
        if (status == MMDB_SUCCESS) {
            printf("== decoder ==\n");
            decoder_fields(&mmdb, "::1.1.1.1");
            decoder_fields(&mmdb, "::4.5.6.7");
            decoder_fields(&mmdb, "::0.0.0.0");
            decoder_fields(&mmdb, "e900::");
            MMDB_close(&mmdb);
        }
    }

    /* ---- ipv4 db + ipv6 lookup ---- */
    {
        char *db = join(tdir, "MaxMind-DB-test-ipv4-24.mmdb");
        MMDB_s mmdb;
        int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
        printf("== open MaxMind-DB-test-ipv4-24.mmdb ==\n%d %s\n", status, MMDB_strerror(status));
        free(db);
        if (status == MMDB_SUCCESS) {
            int gai_error = 0, mmdb_error = 0;
            MMDB_lookup_result_s r =
                MMDB_lookup_string(&mmdb, "::1", &gai_error, &mmdb_error);
            printf("== ipv6-in-ipv4 ==\nfound=%d netmask=%u gai=%d mmdb_err=%d %s\n",
                   r.found_entry ? 1 : 0, r.netmask, gai_error, mmdb_error,
                   MMDB_strerror(mmdb_error));
            MMDB_close(&mmdb);
        }
    }

    /* ---- corrupt databases ---- */
    {
        char *db = join(tdir, "MaxMind-DB-test-broken-pointers-24.mmdb");
        MMDB_s mmdb;
        int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
        printf("== open broken-pointers-24 ==\n%d %s\n", status, MMDB_strerror(status));
        free(db);
        if (status == MMDB_SUCCESS) {
            int gai_error = 0, mmdb_error = 0;
            MMDB_lookup_result_s r =
                MMDB_lookup_string(&mmdb, "1.1.1.16", &gai_error, &mmdb_error);
            printf("lookup 1.1.1.16: found=%d gai=%d mmdb_err=%d\n",
                   r.found_entry ? 1 : 0, gai_error, mmdb_error);
            if (r.found_entry) {
                MMDB_entry_data_list_s *list = NULL;
                int s = MMDB_get_entry_data_list(&r.entry, &list);
                printf("get_entry_data_list: %d %s\n", s, MMDB_strerror(s));
                MMDB_free_entry_data_list(list);
            }
            r = MMDB_lookup_string(&mmdb, "1.1.1.32", &gai_error, &mmdb_error);
            printf("lookup 1.1.1.32: found=%d gai=%d mmdb_err=%d %s\n",
                   r.found_entry ? 1 : 0, gai_error, mmdb_error,
                   MMDB_strerror(mmdb_error));
            MMDB_close(&mmdb);
        }
    }
    {
        char *db = join(tdir, "MaxMind-DB-test-broken-search-tree-24.mmdb");
        MMDB_s mmdb;
        int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
        printf("== open broken-search-tree-24 ==\n%d %s\n", status, MMDB_strerror(status));
        free(db);
        if (status == MMDB_SUCCESS) {
            int gai_error = 0, mmdb_error = 0;
            MMDB_lookup_string(&mmdb, "1.1.1.1", &gai_error, &mmdb_error);
            printf("lookup 1.1.1.1: gai=%d mmdb_err=%d %s\n", gai_error, mmdb_error,
                   MMDB_strerror(mmdb_error));
            MMDB_close(&mmdb);
        }
    }

    /* ---- bad-data corpus ---- */
    {
        const char *baddata[] = {
            "libmaxminddb-deep-nesting.mmdb",
            "libmaxminddb-deep-array-nesting.mmdb",
            "libmaxminddb-oversized-array.mmdb",
            "libmaxminddb-oversized-map.mmdb",
            "libmaxminddb-offset-integer-overflow.mmdb",
            "libmaxminddb-empty-array-last-in-metadata.mmdb",
            "libmaxminddb-empty-map-last-in-metadata.mmdb",
            "libmaxminddb-corrupt-search-tree.mmdb",
            "libmaxminddb-uint64-max-epoch.mmdb",
            NULL};
        printf("== bad-data ==\n");
        for (int i = 0; baddata[i] != NULL; i++) {
            char *bd = join(tdir, "bad-data");
            char *db = join(bd, baddata[i]);
            MMDB_s mmdb;
            memset(&mmdb, 0, sizeof(mmdb));
            int status = MMDB_open(db, MMDB_MODE_MMAP, &mmdb);
            printf("open %s: %d %s\n", baddata[i], status, MMDB_strerror(status));
            free(db);
            free(bd);
            if (status == MMDB_SUCCESS) {
                MMDB_entry_data_list_s *list = NULL;
                int s = MMDB_get_metadata_as_entry_data_list(&mmdb, &list);
                printf("  metadata list: %d %s\n", s, MMDB_strerror(s));
                if (s == MMDB_SUCCESS) {
                    int dstatus = MMDB_dump_entry_data_list(stdout, list, 0);
                    printf("  dump_status=%d\n", dstatus);
                    MMDB_free_entry_data_list(list);
                }
                MMDB_close(&mmdb);
            }
        }
    }

    printf("== done ==\n");
    return 0;
}

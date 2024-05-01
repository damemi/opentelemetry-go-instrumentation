#include "arguments.h"
#include "span_context.h"
#include "go_context.h"
#include "go_types.h"
#include "uprobe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_HOSTNAME_SIZE 256
#define MAX_PROTO_SIZE 8
#define MAX_PATH_SIZE 100
#define MAX_SCHEME_SIZE 8
#define MAX_URL_HOST_SIZE 8
#define MAX_OPAQUE_SIZE 8
#define MAX_RAWPATH_SIZE 8
#define MAX_RAWQUERY_SIZE 8
#define MAX_FRAGMENT_SIZE 8
#define MAX_RAWFRAGMENT_SIZE 8
#define MAX_USERNAME_SIZE 8
#define MAX_METHOD_SIZE 10
#define MAX_CONCURRENT 50

struct http_request_t {
    BASE_SPAN_PROPERTIES
    char host[MAX_HOSTNAME_SIZE];
    char proto[MAX_PROTO_SIZE];
    u64 status_code;
    char method[MAX_METHOD_SIZE];
    char path[MAX_PATH_SIZE];
    char scheme[MAX_SCHEME_SIZE];
    char url_host[MAX_URL_HOST_SIZE];
    char opaque[MAX_OPAQUE_SIZE];
    char raw_path[MAX_RAWPATH_SIZE];
    int omit_host;
    int force_query;
    char raw_query[MAX_RAWQUERY_SIZE];
    char fragment[MAX_FRAGMENT_SIZE];
    char raw_fragment[MAX_RAWFRAGMENT_SIZE];
    char username[MAX_USERNAME_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, struct http_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} http_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct map_bucket));
	__uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct http_request_t));
    __uint(max_entries, 1);
} http_client_uprobe_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void*); // the headers ptr
	__type(value, void*); // request key, goroutine or context ptr
	__uint(max_entries, MAX_CONCURRENT);
} http_headers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Injected in init
volatile const u64 method_ptr_pos;
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 headers_ptr_pos;
volatile const u64 ctx_ptr_pos;
volatile const u64 buckets_ptr_pos;
volatile const u64 status_code_pos;
volatile const u64 request_host_pos;
volatile const u64 request_proto_pos;
volatile const u64 scheme_pos;
volatile const u64 url_host_pos;
volatile const u64 opaque_pos;
volatile const u64 user_ptr_pos;
volatile const u64 raw_path_pos;
volatile const u64 omit_host_pos;
volatile const u64 force_query_pos;
volatile const u64 raw_query_pos;
volatile const u64 fragment_pos;
volatile const u64 raw_fragment_pos;
volatile const u64 username_pos;
volatile const u64 io_writer_buf_ptr_pos;
volatile const u64 io_writer_n_pos;

static __always_inline long inject_header(void* headers_ptr, struct span_context* propagated_ctx) {
    // Read the key-value count - this field must be the first one in the hmap struct as documented in src/runtime/map.go
    u64 curr_keyvalue_count = 0;
    long res = bpf_probe_read_user(&curr_keyvalue_count, sizeof(curr_keyvalue_count), headers_ptr);

    if (res < 0) {
        bpf_printk("Couldn't read map key-value count from user");
        return -1;
    }

    if (curr_keyvalue_count >= 8) {
        bpf_printk("Map size is bigger than 8, skipping context propagation");
        return -1;
    }

    // Get pointer to temp bucket struct we store in a map (avoiding large local variable on the stack)
    // Performing read-modify-write on the bucket
    u32 map_id = 0;
    struct map_bucket *bucket_map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!bucket_map_value) {
        return -1;
    }

    void *buckets_ptr_ptr = (void*) (headers_ptr + buckets_ptr_pos);
    void *bucket_ptr = 0; // The actual pointer to the buckets

    if (curr_keyvalue_count == 0) {
        // No key-value pairs in the Go map, need to "allocate" memory for the user
        bucket_ptr = write_target_data(bucket_map_value, sizeof(struct map_bucket));
        if (bucket_ptr == NULL) {
            bpf_printk("inject_header: Failed to write bucket to user");
            return -1;
        }
        // Update the buckets pointer in the hmap struct to point to newly allocated bucket
        res = bpf_probe_write_user(buckets_ptr_ptr, &bucket_ptr, sizeof(bucket_ptr));
        if (res < 0) {
            bpf_printk("Failed to update the map bucket pointer for the user");
            return -1;
        }
    } else {
        // There is at least 1 key-value pair, hence the bucket pointer from the user is valid
        // Read the bucket pointer
        res = bpf_probe_read_user(&bucket_ptr, sizeof(bucket_ptr), buckets_ptr_ptr);
        // Read the user's bucket to the eBPF map entry
        bpf_probe_read_user(bucket_map_value, sizeof(struct map_bucket), bucket_ptr);
    }

    u8 bucket_index = curr_keyvalue_count & 0x7;

    char traceparent_tophash = 0xee;
    bucket_map_value->tophash[bucket_index] = traceparent_tophash;

    // Prepare the key string for the user
    char key[W3C_KEY_LENGTH] = "traceparent";
    void *ptr = write_target_data(key, W3C_KEY_LENGTH);
    if (ptr == NULL) {
        bpf_printk("inject_header: Failed to write key to user");
        return -1;
    }
    bucket_map_value->keys[bucket_index] = (struct go_string) {.len = W3C_KEY_LENGTH, .str = ptr};

    // Prepare the value string slice
    // First the value string which constains the span context
    char val[W3C_VAL_LENGTH];
    span_context_to_w3c_string(propagated_ctx, val);
    ptr = write_target_data(val, sizeof(val));
    if(ptr == NULL) {
        bpf_printk("inject_header: Failed to write value to user");
        return -1;
    }

    // The go string pointing to the above val
    struct go_string header_value = {.len = W3C_VAL_LENGTH, .str = ptr};
    ptr = write_target_data((void*)&header_value, sizeof(header_value));
    if(ptr == NULL) {
        bpf_printk("inject_header: Failed to write go_string to user");
        return -1;
    }

    // Last, go_slice pointing to the above go_string
    bucket_map_value->values[bucket_index] = (struct go_slice) {.array = ptr, .cap = 1, .len = 1};

    // Update the map header count field
    curr_keyvalue_count += 1;
    res = bpf_probe_write_user(headers_ptr, &curr_keyvalue_count, sizeof(curr_keyvalue_count));
    if (res < 0) {
        bpf_printk("Failed to update key-value count in map header");
        return -1;
    }

    // Update the bucket
    res = bpf_probe_write_user(bucket_ptr, bucket_map_value, sizeof(struct map_bucket));
    if (res < 0) {
        bpf_printk("Failed to update bucket content");
        return -1;
    }

    bpf_memset((unsigned char *)bucket_map_value, sizeof(struct map_bucket), 0);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func net/http/transport.roundTrip(req *Request) (*Response, error)
SEC("uprobe/Transport_roundTrip")
int uprobe_Transport_roundTrip(struct pt_regs *ctx) {
    u64 request_pos = 2;
    void *req_ptr = get_argument(ctx, request_pos);

    // Get parent if exists
    void *context_ptr_val = get_Go_context(ctx, 2, ctx_ptr_pos, false);
    if (context_ptr_val == NULL)
    {
        return 0;
    }
    void *key = get_consistent_key(ctx, context_ptr_val);
    void *httpReq_ptr = bpf_map_lookup_elem(&http_events, &key);
    if (httpReq_ptr != NULL)
    {
        bpf_printk("uprobe/Transport_RoundTrip already tracked with the current context");
        return 0;
    }

    u32 map_id = 0;
    struct http_request_t *httpReq = bpf_map_lookup_elem(&http_client_uprobe_storage_map, &map_id);
    if (httpReq == NULL)
    {
        bpf_printk("uprobe/Transport_roundTrip: httpReq is NULL");
        return 0;
    }

    __builtin_memset(httpReq, 0, sizeof(struct http_request_t));
    httpReq->start_time = bpf_ktime_get_ns();

    struct span_context *parent_span_ctx = get_parent_span_context(context_ptr_val);
    if (parent_span_ctx != NULL) {
        bpf_probe_read(&httpReq->psc, sizeof(httpReq->psc), parent_span_ctx);
        copy_byte_arrays(httpReq->psc.TraceID, httpReq->sc.TraceID, TRACE_ID_SIZE);
        generate_random_bytes(httpReq->sc.SpanID, SPAN_ID_SIZE);
    } else {
        httpReq->sc = generate_span_context();
    }

    if (!get_go_string_from_user_ptr((void *)(req_ptr+method_ptr_pos), httpReq->method, sizeof(httpReq->method))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get method from request");
        return 0;
    }

    // get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr+url_ptr_pos));
    if (!get_go_string_from_user_ptr((void *)(url_ptr+path_ptr_pos), httpReq->path, sizeof(httpReq->path))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get path from Request.URL");
    }

    // get scheme from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+scheme_pos), httpReq->scheme, sizeof(httpReq->scheme))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get scheme from Request.URL");
    }

    // get host from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+url_host_pos), httpReq->url_host, sizeof(httpReq->url_host))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get host from Request.URL");
    }

    // get opaque from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+opaque_pos), httpReq->opaque, sizeof(httpReq->opaque))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get opaque from Request.URL");
    }

    // get RawPath from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+raw_path_pos), httpReq->raw_path, sizeof(httpReq->raw_path))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get RawPath from Request.URL");
    }

/*
    // get OmitHost from Request.URL
    if (!bpf_probe_read_user(httpReq->omit_host, sizeof(httpReq->omit_host), (void *)(url_ptr+omit_host_pos))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get OmitHost from Request.URL");
        return 0;
    }

    // get ForceQuery from Request.URL
    if (!bpf_probe_read_user(httpReq->force_query, sizeof(httpReq->force_query), (void *)(url_ptr+force_query_pos))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get ForceQuery from Request.URL");
        return 0;
    }
    */

    // get RawQuery from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+raw_query_pos), httpReq->raw_query, sizeof(httpReq->raw_query))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get RawQuery from Request.URL");
    }

    // get Fragment from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+fragment_pos), httpReq->fragment, sizeof(httpReq->fragment))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get Fragment from Request.URL");
    }

    // get RawFragment from Request.URL
    if (!get_go_string_from_user_ptr((void *)(url_ptr+raw_fragment_pos), httpReq->raw_fragment, sizeof(httpReq->raw_fragment))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get RawFragment from Request.URL");
    }

    // get username from Request.URL.User
    void *user_ptr = 0;
    bpf_probe_read(&user_ptr, sizeof(user_ptr), (void *)(url_ptr+user_ptr_pos));
    if (!get_go_string_from_user_ptr((void *)(user_ptr+username_pos), httpReq->username, sizeof(httpReq->username))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get RawQuery from Request.URL");
    }

    // get host from Request
    if (!get_go_string_from_user_ptr((void *)(req_ptr+request_host_pos), httpReq->host, sizeof(httpReq->host))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get host from Request");
    }

    // get proto from Request
    if (!get_go_string_from_user_ptr((void *)(req_ptr+request_proto_pos), httpReq->proto, sizeof(httpReq->proto))) {
        bpf_printk("uprobe_Transport_roundTrip: Failed to get proto from Request");
    }

    // get headers from Request
    void *headers_ptr = 0;
    bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void *)(req_ptr+headers_ptr_pos));
    if (headers_ptr) {
        bpf_map_update_elem(&http_headers, &headers_ptr, &key, 0);
    }

    // Write event
    bpf_map_update_elem(&http_events, &key, httpReq, 0);
    start_tracking_span(context_ptr_val, &httpReq->sc);
    return 0;
}

// This instrumentation attaches uretprobe to the following function:
// func net/http/transport.roundTrip(req *Request) (*Response, error)
SEC("uprobe/Transport_roundTrip")
int uprobe_Transport_roundTrip_Returns(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    void *req_ctx_ptr = get_Go_context(ctx, 2, ctx_ptr_pos, false);
    void *key = get_consistent_key(ctx, req_ctx_ptr);

    struct http_request_t *http_req_span = bpf_map_lookup_elem(&http_events, &key);
    if (http_req_span == NULL) {
        bpf_printk("probe_Transport_roundTrip_Returns: entry_state is NULL");
        return 0;
    }

    if (is_register_abi()) {
        // Getting the returned response
        void *resp_ptr = get_argument(ctx, 1);
        // Get status code from response
        bpf_probe_read(&http_req_span->status_code, sizeof(http_req_span->status_code), (void *)(resp_ptr + status_code_pos));
    }

    http_req_span->end_time = end_time;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, http_req_span, sizeof(*http_req_span));
    stop_tracking_span(&http_req_span->sc, &http_req_span->psc);

    bpf_map_delete_elem(&http_events, &key);
    return 0;
}

#ifndef NO_HEADER_PROPAGATION
// This instrumentation attaches uprobe to the following function:
// func (h Header) net/http.Header.writeSubset(w io.Writer, exclude map[string]bool, trace *httptrace.ClientTrace) error
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    u64 headers_pos = 1;
    void *headers_ptr = get_argument(ctx, headers_pos);

    u64 io_writer_pos = 3;
    void *io_writer_ptr = get_argument(ctx, io_writer_pos);

    void **key_ptr = bpf_map_lookup_elem(&http_headers, &headers_ptr);
    if (key_ptr) {
        void *key = *key_ptr;

        struct http_request_t *http_req_span = bpf_map_lookup_elem(&http_events, &key);
        if (http_req_span) {
            char tp[W3C_VAL_LENGTH];
            span_context_to_w3c_string(&http_req_span->sc, tp);

            void *buf_ptr = 0;
            bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_ptr + io_writer_buf_ptr_pos)); // grab buf ptr
            if (!buf_ptr) {
                bpf_printk("uprobe_writeSubset: Failed to get buf from io writer");
                goto done;
            }

            s64 size = 0;
            if (bpf_probe_read(&size, sizeof(s64), (void *)(io_writer_ptr + io_writer_buf_ptr_pos + offsetof(struct go_slice, cap)))) { // grab capacity
                bpf_printk("uprobe_writeSubset: Failed to get size from io writer");
                goto done;
            }

            s64 len = 0;
            if (bpf_probe_read(&len, sizeof(s64), (void *)(io_writer_ptr + io_writer_n_pos))) { // grab len
                bpf_printk("uprobe_writeSubset: Failed to get len from io writer");
                goto done;
            }

            if (len < (size - W3C_VAL_LENGTH - W3C_KEY_LENGTH - 4)) { // 4 = strlen(":_") + strlen("\r\n")
                char tp_str[W3C_KEY_LENGTH + 2 + W3C_VAL_LENGTH + 2] = "Traceparent: ";
                char end[2] = "\r\n";
                __builtin_memcpy(&tp_str[W3C_KEY_LENGTH + 2], tp, sizeof(tp));
                __builtin_memcpy(&tp_str[W3C_KEY_LENGTH + 2 + W3C_VAL_LENGTH], end, sizeof(end));
                if (bpf_probe_write_user(buf_ptr + (len & 0x0ffff), tp_str, sizeof(tp_str))) {
                    bpf_printk("uprobe_writeSubset: Failed to write trace parent key in buffer");
                    goto done;
                }
                len += W3C_KEY_LENGTH + 2 + W3C_VAL_LENGTH + 2;
                if (bpf_probe_write_user((void *)(io_writer_ptr + io_writer_n_pos), &len, sizeof(len))) {
                    bpf_printk("uprobe_writeSubset: Failed to change io writer n");
                    goto done;
                }
            }
        }
    }

done:
    bpf_map_delete_elem(&http_headers, &headers_ptr);
    return 0;
}
#else
// Not used at all, empty stub needed to ensure both versions of the bpf program are
// able to compile with bpf2go. The userspace code will avoid loading the probe if
// context propagation is not enabled.
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    return 0;
}
#endif

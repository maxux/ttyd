#include <string.h>
#include <libwebsockets.h>
#include <json.h>
#include <signal.h>
#include <pthread.h>

#include "server.h"
#include "html.h"
#include "utils.h"

#undef lwsl_notice
#undef lwsl_err
#undef lwsl_warn
#define lwsl_notice printf
#define lwsl_err printf
#define lwsl_warn printf

struct callback_response {
    struct lws *wsi;
    struct pss_http *pss;
    unsigned char *buffer;
    unsigned char *p;
    unsigned char *end;
};


int check_auth(struct lws *wsi) {
    if(server->credential == NULL)
        return 0;

    int hdr_length = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
    char buf[hdr_length + 1];
    int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_AUTHORIZATION);
    if (len > 0) {
        // extract base64 text from authorization header
        char *ptr = &buf[0];
        char *token, *b64_text = NULL;
        int i = 1;
        while ((token = strsep(&ptr, " ")) != NULL) {
            if (strlen(token) == 0)
                continue;
            if (i++ == 2) {
                b64_text = token;
                break;
            }
        }
        if (b64_text != NULL && !strcmp(b64_text, server->credential))
            return 0;
    }

    unsigned char buffer[1024 + LWS_PRE], *p, *end;
    p = buffer + LWS_PRE;
    end = p + sizeof(buffer) - LWS_PRE;

    if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end))
        return 1;
    if (lws_add_http_header_by_token(wsi,
                                     WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
                                     (unsigned char *) "Basic realm=\"ttyd\"",
                                     18, &p, end))
        return 1;
    if (lws_add_http_header_content_length(wsi, 0, &p, end))
        return 1;
    if (lws_finalize_http_header(wsi, &p, end))
        return 1;
    if (lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
        return 1;

    return -1;
}

static int http_response(struct callback_response *r, char *ctype, size_t length, char *buffer) {
    if(lws_add_http_header_status(r->wsi, HTTP_STATUS_OK, &r->p, r->end))
        return 1;

    if(lws_add_http_header_by_token(r->wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, ctype, strlen(ctype), &r->p, r->end))
        return 1;

    if(lws_add_http_header_content_length(r->wsi, length, &r->p, r->end))
        return 1;

    if(lws_finalize_http_header(r->wsi, &r->p, r->end))
        return 1;

    if(lws_write(r->wsi, r->buffer + LWS_PRE, r->p - (r->buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
        return 1;

    if(!buffer)
        return 0;

    r->pss->buffer = r->pss->ptr = strdup(buffer);
    r->pss->len = length;
    lws_callback_on_writable(r->wsi);

    return 0;
}

//
// json status
//
char *http_response_json_ok() {
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string("success"));

    char *jsondumps = strdup(json_object_to_json_string(root));
    json_object_put(root);

    return jsondumps;
}

char *http_response_json_error(char *msg) {
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string("error"));
    json_object_object_add(root, "reason", json_object_new_string(msg));

    char *jsondumps = strdup(json_object_to_json_string(root));
    json_object_put(root);

    return jsondumps;
}

//
// methods
//
static inline int http_method_is_get(struct lws *wsi) {
    return lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
}

static inline int http_method_is_post(struct lws *wsi) {
    return lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI);
}

//
// routing
//
static int routing_get_root(struct callback_response *r) {
    lws_return_http_status(r->wsi, HTTP_STATUS_NOT_FOUND, NULL);
    return 0;
}

static int routing_get_pid(struct callback_response *r, char *pid) {
    if(strlen(pid) == 0) {
        lwsl_err("pid not defined\n");
        lws_return_http_status(r->wsi, HTTP_STATUS_NOT_FOUND, NULL);
        return 1;
    }

    lwsl_notice("requesting to attach pid <%s>\n", pid);

    // checking for pid validity, this is actually not an error
    // the client will not be able to connect later via the websocket
    // anyway, but we can at least ensure it's an integer...
    if(atoi(pid) < 1) {
        lwsl_err("invalid pid\n");
        lws_return_http_status(r->wsi, HTTP_STATUS_NOT_FOUND, NULL);
        return 1;
    }

    if(server->index == NULL)
        return http_response(r, "text/html", index_html_len, index_html);

    int n = lws_serve_http_file(r->wsi, server->index, "text/html", NULL, 0);
    if(n < 0 || (n > 0 && lws_http_transaction_completed(r->wsi)))
        return 1;
}

static int routing_get_auth_token(struct callback_response *r) {
    char buf[512];

    size_t n = server->credential != NULL ? sprintf(buf, "var tty_auth_token = '%s';", server->credential) : 0;
    return http_response(r, "application/javascript", n, n ? buf : NULL);
}

// api

static int routing_get_api_processes(struct callback_response *r) {
    struct json_object *root = json_object_new_object();
    struct json_object *processes = json_object_new_array();

    struct tty_process *proc;

    pthread_mutex_lock(&server->mutex);

    LIST_FOREACH(proc, &server->processes, list) {
        struct json_object *process = json_object_new_object();

        json_object_object_add(process, "pid", json_object_new_int64(proc->pid));
        json_object_object_add(process, "command", json_object_new_string(proc->command));
        json_object_object_add(process, "running", json_object_new_boolean(proc->running));

        json_object_array_add(processes, process);
    }

    pthread_mutex_unlock(&server->mutex);

    json_object_object_add(root, "processes", processes);

    char *jsondumps = strdup(json_object_to_json_string(root));
    json_object_put(root);

    int value = http_response(r, "application/json", strlen(jsondumps), jsondumps);
    free(jsondumps);

    return value;

}

static int routing_get_api_process_start(struct callback_response *r) {
    char cmdline[512];
    char *binary = NULL;
    char **argv = NULL;
    int argc = 0;

    while(lws_hdr_copy_fragment(r->wsi, cmdline, sizeof(cmdline), WSI_TOKEN_HTTP_URI_ARGS, argc) > 0) {
        if(strncmp(cmdline, "arg[]=", 6) == 0)
            argc += 1;
    }

    if(argc == 0) {
        char *status = http_response_json_error("missing cmdline");

        int value = http_response(r, "application/json", strlen(status), status);
        free(status);

        return value;
    }

    argv = xmalloc(sizeof(char *) * argc);
    int j = 0;

    for(int i = 0; ; i++) {
        if(lws_hdr_copy_fragment(r->wsi, cmdline, sizeof(cmdline), WSI_TOKEN_HTTP_URI_ARGS, i) < 0)
            break;

        if(strncmp(cmdline, "arg[]=", 6) == 0) {
            argv[j] = strdup(cmdline + 6);
            j += 1;
        }
    }

    lwsl_warn("starting process: %s [with %d args]\n", argv[0], argc - 1);
    struct tty_process *proc = tty_server_attach_process(server, argc, argv);

    // waiting for process to be ready
    pthread_mutex_lock(&proc->mutex);

    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string("success"));
    json_object_object_add(root, "pid", json_object_new_int64(proc->pid));

    pthread_mutex_unlock(&proc->mutex);

    char *jsondumps = strdup(json_object_to_json_string(root));
    json_object_put(root);

    int value = http_response(r, "application/json", strlen(jsondumps), jsondumps);
    free(jsondumps);

    return value;
}

static int routing_get_api_process_stop(struct callback_response *r) {
    const char *ppid;
    char pid[32];

    if(!(ppid = lws_get_urlarg_by_name(r->wsi, "pid=", pid, sizeof(pid)))) {
        char *status = http_response_json_error("missing pid");
        int value = http_response(r, "application/json", strlen(status), status);
        free(status);
        return value;
    }

    int ipid = atoi(ppid);
    lwsl_warn("requesing stopping process: %d\n", ipid);

    // looking for and killing processes
    struct tty_process *process;
    if(!(process = process_getby_pid(ipid, 1))) {
        char *status = http_response_json_error("invalid pid");
        int value = http_response(r, "application/json", strlen(status), status);
        free(status);
        return value;
    }

    lwsl_warn("killing process: %d\n", process->pid);
    kill(process->pid, SIGTERM);
    process->running = false;

    char *status = http_response_json_ok();
    int value = http_response(r, "application/json", strlen(status), status);
    free(status);

    return value;
}

static int routing_get_api_process_logs(struct callback_response *r) {
    const char *ppid;
    char pid[32];

    if(!(ppid = lws_get_urlarg_by_name(r->wsi, "pid=", pid, sizeof(pid)))) {
        char *status = http_response_json_error("missing pid");
        int value = http_response(r, "application/json", strlen(status), status);
        free(status);
        return value;
    }

    int ipid = atoi(ppid);
    lwsl_warn("requesing stopping process: %d\n", ipid);

    // killing processes
    struct tty_process *process;
    if(!(process = process_getby_pid(ipid, 1))) {
        char *status = http_response_json_error("invalid pid");
        int value = http_response(r, "application/json", strlen(status), status);
        free(status);
        return value;
    }

    // fetching logs.
    buffer_t *logs = circular_get(process->logs, 0);

    int value = http_response(r, "text/plain", logs->length, logs->buffer);
    buffer_free(logs);

    return value;
}


//
// callback
//
int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct pss_http *pss = (struct pss_http *) user;
    unsigned char buffer[4096 + LWS_PRE], *p, *end;
    char buf[256], name[100], rip[50];

    struct callback_response r = {
        .wsi = wsi,
        .pss = pss,
        .buffer = buffer,
        .p = p,
        .end = end,
    };

    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            if(len < 1) {
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
                goto try_to_reuse;
            }

            // initialize context
            r.p = r.buffer + LWS_PRE;
            r.end = r.p + sizeof(buffer) - LWS_PRE;

            if(http_method_is_get(wsi))
                goto routing_get;

            /*
            if(http_method_is_post(wsi))
                goto routing_post;
            */

            // method not allowed
            lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
            goto try_to_reuse;

            //
            // GET
            //
routing_get:
            snprintf(pss->path, sizeof(pss->path), "%s", (const char *)in);
            lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, sizeof(name), rip, sizeof(rip));
            lwsl_notice("HTTP %s - %s (%s)\n", (char *) in, rip, name);

            printf(">> %s\n", pss->path);

            switch (check_auth(wsi)) {
                case 0:
                    break;
                case -1:
                    goto try_to_reuse;
                case 1:
                default:
                    return 1;
            }


            if(strcmp(pss->path, "/") == 0)
                return routing_get_root(&r);

            if(strncmp(pss->path, "/pid/", 5) == 0)
                return routing_get_pid(&r, pss->path + 5);

            if(strncmp(pss->path, "/auth_token.js", 14) == 0)
                return routing_get_auth_token(&r);

            if(strcmp(pss->path, "/api/processes") == 0)
                return routing_get_api_processes(&r);

            if(strcmp(pss->path, "/api/process/start") == 0)
                return routing_get_api_process_start(&r);

            if(strcmp(pss->path, "/api/process/stop") == 0)
                return routing_get_api_process_stop(&r);

            if(strcmp(pss->path, "/api/process/logs") == 0)
                return routing_get_api_process_logs(&r);


            // anything else, not found
            lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
            goto try_to_reuse;
        }

        case LWS_CALLBACK_HTTP_WRITEABLE:
            if (pss->len <= 0)
                goto try_to_reuse;

            if (pss ->ptr - pss->buffer == pss->len) {
                if (pss->buffer != (char *) index_html) free(pss->buffer);
                goto try_to_reuse;
            }

            int n = sizeof(buffer) - LWS_PRE;
            if (pss->ptr - pss->buffer + n > pss->len)
                n = (int) (pss->len - (pss->ptr - pss->buffer));

            memcpy(buffer + LWS_PRE, pss->ptr, n);
            pss->ptr += n;
            if (lws_write_http(wsi, buffer + LWS_PRE, (size_t) n) < n) {
                if (pss->buffer != (char *) index_html) free(pss->buffer);
                return -1;
            }

            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
            if (!len || (SSL_get_verify_result((SSL *) in) != X509_V_OK)) {
                int err = X509_STORE_CTX_get_error((X509_STORE_CTX *) user);
                int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *) user);
                const char *msg = X509_verify_cert_error_string(err);
                lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
                return 1;
            }
            break;
        default:
            break;
    }

    return 0;

    /* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
    if (lws_http_transaction_completed(wsi))
        return -1;

    return 0;
}

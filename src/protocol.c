#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/types.h>

#include <libwebsockets.h>
#include <json.h>

#include "server.h"
#include "utils.h"

// initial message list
char initial_cmds[] = {
    SET_WINDOW_TITLE,
    SET_RECONNECT,
    SET_PREFERENCES
};

int
send_initial_message(struct lws *wsi, int index) {
    unsigned char message[LWS_PRE + 1 + 4096];
    unsigned char *p = &message[LWS_PRE];
    char buffer[128];
    int n = 0;

    // FIXME
    struct tty_process *process = LIST_FIRST(&server->processes);

    char cmd = initial_cmds[index];
    switch(cmd) {
        case SET_WINDOW_TITLE:
            gethostname(buffer, sizeof(buffer) - 1);
            n = sprintf((char *) p, "%c%s (%s)", cmd, process->command, buffer);
            break;

        case SET_RECONNECT:
            n = sprintf((char *) p, "%c%d", cmd, server->reconnect);
            break;
        case SET_PREFERENCES:
            n = sprintf((char *) p, "%c%s", cmd, server->prefs_json);
            break;
        default:
            break;
    }

    return lws_write(wsi, p, (size_t) n, LWS_WRITE_BINARY);
}

bool parse_window_size(const char *json, struct winsize *size) {
    int columns, rows;
    json_object *obj = json_tokener_parse(json);
    struct json_object *o = NULL;

    if(!json_object_object_get_ex(obj, "columns", &o)) {
        printf("[-] window size: columns field not exists, json: %s\n", json);
        return false;
    }

    columns = json_object_get_int(o);
    if(!json_object_object_get_ex(obj, "rows", &o)) {
        printf("[-] window size: rows field not exists, json: %s\n", json);
        return false;
    }

    rows = json_object_get_int(o);
    json_object_put(obj);

    memset(size, 0, sizeof(struct winsize));
    size->ws_col = (unsigned short) columns;
    size->ws_row = (unsigned short) rows;

    return true;
}

bool check_host_origin(struct lws *wsi) {
    int origin_length = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN);
    char buf[origin_length + 1];
    memset(buf, 0, sizeof(buf));
    int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_ORIGIN);
    if (len <= 0) {
        return false;
    }

    const char *prot, *address, *path;
    int port;
    if (lws_parse_uri(buf, &prot, &address, &port, &path))
        return false;
    if (port == 80 || port == 443) {
        sprintf(buf, "%s", address);
    } else {
        sprintf(buf, "%s:%d", address, port);
    }

    int host_length = lws_hdr_total_length(wsi, WSI_TOKEN_HOST);
    if ((size_t) host_length != strlen(buf))
        return false;

    char host_buf[host_length + 1];
    memset(host_buf, 0, sizeof(host_buf));
    len = lws_hdr_copy(wsi, host_buf, sizeof(host_buf), WSI_TOKEN_HOST);

    return len > 0 && strcasecmp(buf, host_buf) == 0;
}

void tty_client_remove(struct tty_client *client) {
    struct tty_client *iterator;

    LIST_FOREACH(iterator, &server->clients, list) {
        if (iterator == client) {
            LIST_REMOVE(iterator, list);
            server->client_count--;
            break;
        }
    }
}

void tty_client_destroy(struct tty_client *client) {
    if (!client->running || client->pid <= 0)
        goto cleanup;

    client->running = false;

    client->state = STATE_DONE;

    // do not kill process when client dies

    #if 0
    // kill process and free resource
    lwsl_notice("sending %s (%d) to process %d\n", server->sig_name, server->sig_code, client->pid);
    if (kill(client->pid, server->sig_code) != 0) {
        lwsl_err("kill: %d, errno: %d (%s)\n", client->pid, errno, strerror(errno));
    }
    int status;
    while (waitpid(client->pid, &status, 0) == -1 && errno == EINTR)
        ;
    lwsl_notice("process exited with code %d, pid: %d\n", status, client->pid);
    close(client->pty);
    #endif

cleanup:
    // free the buffer
    if (client->buffer != NULL)
        free(client->buffer);

    // remove from client list
    tty_client_remove(client);
}

int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct tty_client *client = (struct tty_client *) user;
    char buf[256];
    size_t n = 0;

    switch (reason) {
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            if(server->max_clients > 0 && server->client_count == server->max_clients) {
                verbose("[-] callback: tty: refuse to serve ws client due to the --max-clients option\n");
                return 1;
            }

            if(lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI) <= 0) {
                verbose("[-] callback: tty: refuse to serve ws client for wrong path: %s\n", buf);
                return 1;
            }

            /*
            if (strlen(buf) <= strlen(WS_PATH)) {
                lwsl_warn("refuse to serve WS client for illegal ws path: %s\n", buf);
                return 1;
            }
            */

            // initializing client to unknown pid
            client->pid = 0;

            size_t iid = strtoul(buf + sizeof(WS_PATH), NULL, 10);
            verbose("[+] callback: tty: request id: %lu\n", iid);

            struct tty_process *process;
            if(!(process = process_getby_id(iid))) {
                verbose("[+] callback: tty: invalid id, closing connection\n");
                return 1;
            }

            client->process = process;
            client->pid = process->pid;
            client->pty = process->pty;

            if(server->check_origin && !check_host_origin(wsi)) {
                verbose("[-] callback: tty: refuse to serve ws client from different origin due to the --check-origin option\n");
                return 1;
            }

            break;

        case LWS_CALLBACK_ESTABLISHED:
            client->running = false;
            client->initialized = false;
            client->initial_cmd_index = 0;
            client->authenticated = false;
            client->wsi = wsi;
            client->buffer = NULL;
            client->state = STATE_INIT;
            client->pty_len = 0;

            lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi),
                                   client->hostname, sizeof(client->hostname),
                                   client->address, sizeof(client->address));

            LIST_INSERT_HEAD(&server->clients, client, list);
            server->client_count++;
            lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI);

            verbose("[+] callback: tty: established: %s - %s (%s), clients: %d\n", buf, client->address, client->hostname, server->client_count);

            // sending initial logs
            buffer_t *logs = circular_get(client->process->logs, 0);

            memcpy(client->pty_buffer + LWS_PRE + 1, logs->buffer, logs->length);
            client->pty_len = logs->length;
            client->state = STATE_READY;

            // sending effective data
            lws_callback_on_writable(client->wsi);
            buffer_free(logs);

            break;

        case LWS_CALLBACK_SERVER_WRITEABLE:
            if (!client->initialized) {
                printf("[+] callback: client not initialized\n");
                if (client->initial_cmd_index == sizeof(initial_cmds)) {
                    client->initialized = true;
                    lws_callback_on_writable(wsi);
                    break;
                }

                if (send_initial_message(wsi, client->initial_cmd_index) < 0) {
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
                    return -1;
                }

                client->initial_cmd_index++;
                lws_callback_on_writable(wsi);
                return 0;
            }

            if (client->state != STATE_READY) {
                printf("[+] callback: client state not ready\n");
                break;
            }

            // read error or client exited, close connection
            if (client->pty_len <= 0) {
                int status = LWS_CLOSE_STATUS_NORMAL;

                if(client->pty_len != 0)
                    status = LWS_CLOSE_STATUS_UNEXPECTED_CONDITION;

                lws_close_reason(wsi, status, NULL, 0);

                return -1;
            }

            client->pty_buffer[LWS_PRE] = OUTPUT;
            n = (size_t) (client->pty_len + 1);

            if(lws_write(wsi, (unsigned char *) client->pty_buffer + LWS_PRE, n, LWS_WRITE_BINARY) < (int) n)
                fprintf(stderr, "[-] callback: tty: writable: could not write data to ws\n");

            client->state = STATE_DONE;
            break;

        case LWS_CALLBACK_RECEIVE:
            printf("[+] callback: receive data from client\n");
            if (client->buffer == NULL) {
                client->buffer = xmalloc(len);
                client->len = len;
                memcpy(client->buffer, in, len);
            } else {
                client->buffer = xrealloc(client->buffer, client->len + len);
                memcpy(client->buffer + client->len, in, len);
                client->len += len;
            }

            const char command = client->buffer[0];

            // check auth
            if(server->credential != NULL && !client->authenticated && command != JSON_DATA) {
                verbose("[-] callback: tty: ws client not authenticated\n");
                return 1;
            }

            // check if there are more fragmented messages
            if (lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)) {
                return 0;
            }

            switch (command) {
                case INPUT:
                    // pty not initialized
                    if(client->pty == 0)
                        break;

                    // read-only server mode
                    if(server->readonly)
                        return 0;

                    printf("[+] callback: writing to target pty\n");

                    if(write(client->pty, client->buffer + 1, client->len - 1) == -1) {
                        warnp("callback: tty: write input to pty failed");
                        lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
                        return -1;
                    }
                    break;

                case RESIZE_TERMINAL:
                    if (parse_window_size(client->buffer + 1, &client->size) && client->pty > 0) {
                        if (ioctl(client->pty, TIOCSWINSZ, &client->size) == -1) {
                            warnp("ioctl TIOCSWINSZ");
                        }
                    }
                    break;

                case JSON_DATA:
                    if (server->credential != NULL) {
                        json_object *obj = json_tokener_parse(client->buffer);
                        struct json_object *o = NULL;
                        if (json_object_object_get_ex(obj, "AuthToken", &o)) {
                            const char *token = json_object_get_string(o);
                            if (token != NULL && !strcmp(token, server->credential))
                                client->authenticated = true;
                            else
                                verbose("[-] callback: tty; ws authentication failed with token: %s\n", token);
                        }

                        if (!client->authenticated) {
                            lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
                            return -1;
                        }
                    }

                    client->running = true;
                    break;

                default:
                    verbose("[-] callback: tty: ignored unknown message type: %c\n", command);
                    break;
            }

            if(client->buffer != NULL) {
                free(client->buffer);
                client->buffer = NULL;
            }
            break;

        case LWS_CALLBACK_CLOSED:
            tty_client_destroy(client);
            verbose("[+] callback: tty: ws closed from %s (%s), clients: %d\n", client->address, client->hostname, server->client_count);
            break;

        default:
            break;
    }

    return 0;
}

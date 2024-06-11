#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "asgn2_helper_funcs.h"
#include "queue.h"
#include "rwlock.h"

#define QUEUE_SIZE 25
#define BUF_SIZE   2048

pthread_mutex_t f_array_lock;
queue_t *task_queue;
rwlock_t **flocks;
char **fnames;
int tcount = 4;

void fatal_error(char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

void server_error(int client) {
    write_n_bytes(client,
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server Error\n",
        80);
}

bool send_response_from_status(int client, int code, char *oper, char *uri, int id) {
    fprintf(stderr, "%s,%s,%d,%d\n", oper, uri, code, id);
    switch (code) {
    case 200: // 33 + extras (\n included in 33)
        if (write_n_bytes(client, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n", 41) == -1)
            server_error(client);
        return true;
    case 201:
        if (write_n_bytes(client, "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n", 51)
            == -1)
            server_error(client);
        return true;
    case 400:
        if (write_n_bytes(
                client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60)
            == -1)
            server_error(client);
        return true;
    case 403:
        if (write_n_bytes(
                client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56)
            == -1)
            server_error(client);
        return true;
    case 404:
        if (write_n_bytes(
                client, "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n", 56)
            == -1)
            server_error(client);
        return true;
    case 500: server_error(client); return true;
    case 501:
        if (write_n_bytes(client,
                "HTTP/1.1 501 Not Implemented\r\nContent-Length: 16\r\n\r\nNot Implemented\n", 68)
            == -1)
            server_error(client);
        return true;
    case 505:
        if (write_n_bytes(client,
                "HTTP/1.1 505 Version Not Supported\r\nContent-Length: 22\r\n\r\nVersion Not "
                "Supported\n",
                80)
            == -1)
            server_error(client);
        return true;
    }
    return false;
}

int get_capture(char *s, char *cap, regmatch_t *pmatch, int i) {
    const regoff_t cap_size = pmatch[i].rm_eo - pmatch[i].rm_so;
    memcpy(cap, &s[pmatch[i].rm_so], cap_size);
    cap[cap_size] = '\0';

    return cap_size;
}

int parse_request_line(char *buf, int *buf_idx, char *uri, char *meth) {
    regex_t re;
    if (regcomp(&re, "([a-zA-Z]{1,8}) /([a-zA-Z0-9.-]{1,63}) (HTTP/[0-9].[0-9])\r\n", REG_EXTENDED))
        return 500; // Server error
    regmatch_t pmatch[4];
    if (regexec(&re, buf, 4, pmatch, 0))
        return 400; // Bad request
    regfree(&re);

    // Update buf offset
    *buf_idx += pmatch[0].rm_eo;

    // Get method
    get_capture(buf, meth, pmatch, 1);

    // Get uri
    get_capture(buf, uri, pmatch, 2);

    // Get version
    char ver[9];
    get_capture(buf, ver, pmatch, 3);

    if (!(ver[5] == '1' && ver[7] == '1')) {
        return 505; // Version not supported
    }

    return 0;
}

int get(int client, char *uri) {
    int fd = open(uri, O_RDONLY);
    if (fd == -1) {
        switch (errno) {
        case EACCES: return 403;
        case ENOENT: return 404;
        }
        return 500;
    }
    struct stat sb;
    if (stat(uri, &sb) == -1)
        return 500;

    // Check if dir
    if (!S_ISREG(sb.st_mode))
        return 403;
    if (write_n_bytes(client, "HTTP/1.1 200 OK\r\nContent-Length: ", 33) == -1)
        return 500;
    signed int filesize = (signed int) sb.st_size;

    // get length of filesize in bytes
    signed int t = filesize;
    signed int len = 0;
    while (t != 0) {
        t /= 10;
        len++;
    }

    char filesize_str[len + 1];
    sprintf(filesize_str, "%d\r\n\r\n", filesize);
    if (write_n_bytes(client, filesize_str, len + 4) == -1)
        return 500;
    if (pass_n_bytes(fd, client, filesize) == -1)
        return 500;

    close(fd);
    return 0;
}

int parse_header_field(char *buf, int *buf_idx, ssize_t *content_len, int *req_id) {
    // Check for end of header fields
    if (buf[*buf_idx] == '\r' && buf[*buf_idx + 1] == '\n') {
        *buf_idx += 2;
        return 0;
    }

    regex_t re;
    if (regcomp(&re, "([a-zA-Z0-9.-]{1,128}): ([ -~]{0,128})\r\n", REG_EXTENDED))
        return 500; // Server error
    regmatch_t pmatch[3];
    if (regexec(&re, &buf[*buf_idx], 3, pmatch, 0))
        return 400; // Bad request
    regfree(&re);

    // Get method
    char key[129];
    get_capture(&buf[*buf_idx], key, pmatch, 1);

    // Get version
    char val[129];
    get_capture(&buf[*buf_idx], val, pmatch, 2);
    if (strcmp(key, "Content-Length") == 0) {
        *content_len = atoi(val);
    } else if (strcmp(key, "Request-Id") == 0) {
        *req_id = atoi(val);
    }

    // Update buffer offset
    *buf_idx += pmatch[0].rm_eo;

    return 1; // Successful read
}

int put(char *buf, int *buf_idx, int client, char *uri, ssize_t content_len) {
    int code;
    if (access(uri, F_OK) == 0)
        code = 200;
    else
        code = 201;

    int fd = creat(uri, 420);
    if (fd == -1) {
        switch (errno) {
        case ENOENT: return 400;
        }
        return 500;
    }

    ssize_t written = 0;
    int to_write = BUF_SIZE - *buf_idx;
    if (to_write > content_len) {
        to_write = content_len;
    }
    if (content_len > 0 && buf[*buf_idx]) {
        written = write_n_bytes(fd, &buf[*buf_idx], to_write);
    }
    if (written == -1)
        return 500;

    if (pass_n_bytes(client, fd, content_len - written) == -1)
        return 500;

    return code;
}

int get_fname_idx(char *uri) {
    for (int i = 0; i < tcount; i++) {
        if (strcmp(uri, fnames[i]) == 0) {
            return i;
        }
    }
    return -1;
}

void process_connection(int client, int thread_id) {
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);
    int buf_idx = 0;
    int req_id = 404;
    // Read at most 8 (Method) + 64 (URI) + 8 (Version) + 3 (spaces) + 2 (delim) chars for request_line
    if (read_until(client, buf, BUF_SIZE, "\r\n\r\n") == -1) {
        if (!buf[0]) {
            if (errno == 11) {
                send_response_from_status(client, 400, "NONE", "NONE", req_id);
            } else {
                send_response_from_status(client, 500, "NONE", "NONE", req_id);
            }
            return;
        }
    }

    char oper[9];
    char uri[64]; // Remove one because slash not included
    int status = parse_request_line(buf, &buf_idx, uri, oper);

    // Parse header fields, 128 (Key) + 128 (Value) + 1 (Colon) + 1 (Spaces) + 2 (Delim)
    ssize_t content_len = 0;
    while (true) {
        int header_status = parse_header_field(buf, &buf_idx, &content_len, &req_id);
        if (header_status == 0)
            break;
        if (header_status != 1) {
            send_response_from_status(client, header_status, oper, uri, req_id);
            return;
        }
    }
    if (status != 0) {
        send_response_from_status(client, status, oper, uri, req_id);
        return;
    }

    pthread_mutex_lock(&f_array_lock);
    int lock_idx = get_fname_idx(uri);
    rwlock_t *flock;
    if (lock_idx == -1) {
        if (flocks[thread_id] != NULL) {
            rwlock_delete(&flocks[thread_id]);
            free(fnames[thread_id]);
        }
        flock = flocks[thread_id] = rwlock_new(N_WAY, 1);
        char *fname = calloc(65, sizeof(char));
        strcpy(fname, uri);
        fnames[thread_id] = fname;
    } else {
        flock = flocks[lock_idx];
    }
    pthread_mutex_unlock(&f_array_lock);

    // GET
    if (oper[0] == 'G' && oper[1] == 'E' && oper[2] == 'T' && oper[3] == '\0') {
        // Check for message body
        if (buf[buf_idx]) {
            send_response_from_status(client, 400, oper, uri, req_id);
            return;
        }
        reader_lock(flock);
        int get_status = get(client, uri);
        reader_unlock(flock);
        if (get_status == 0) {
            fprintf(stderr, "%s,%s,%d,%d\n", oper, uri, 200, req_id);
        } else {
            send_response_from_status(client, get_status, oper, uri, req_id);
        }
        return;
    }
    // PUT
    if (oper[0] == 'P' && oper[1] == 'U' && oper[2] == 'T' && oper[3] == '\0') {
        writer_lock(flock);
        int put_status = put(buf, &buf_idx, client, uri, content_len);
        writer_unlock(flock);
        send_response_from_status(client, put_status, oper, uri, req_id);
        return;
    }
    send_response_from_status(client, 501, oper, uri, req_id); // Not implemented
}

void run_server(Listener_Socket *server) {
    int client;
    while (true) {
        client = listener_accept(server);
        int *fd = malloc(sizeof(int));
        *fd = client;

        queue_push(task_queue, (void *) fd);
    }
}

void *listen_for_task(void *t_id) {
    int *sock;
    while (true) {
        queue_pop(task_queue, (void **) &sock);

        process_connection(*sock, *(int *) t_id);
        if (close(*sock) == -1) {
            fatal_error("Error closing client.");
        }
    }
}

int main(int argc, char **argv) {
    if (argc <= 1)
        fatal_error("Add more command ops");

    int opt;
    char *end;
    while ((opt = getopt(argc, argv, "t:")) != -1) {
        switch (opt) {
        case 't': tcount = strtol(optarg, &end, 10); break;
        case '?': fatal_error("Unknown option.");
        }
    }
    task_queue = queue_new(QUEUE_SIZE);
    pthread_mutex_init(&f_array_lock, NULL);
    flocks = calloc(tcount, sizeof(rwlock_t *));
    fnames = calloc(tcount, sizeof(char *));
    for (int i = 0; i < tcount; i++) {
        fnames[i] = "";
    }

    // Init threads
    pthread_t *threads = malloc(tcount * sizeof(pthread_t));
    int *t_ids = calloc(tcount, sizeof(int));
    for (int i = 0; i < tcount; i++) {
        t_ids[i] = i;
        if (pthread_create(&threads[i], NULL, &listen_for_task, &t_ids[i]) != 0) {
            fatal_error("Error creating threads.");
        }
    }

    Listener_Socket server_sock;
    if (listener_init(&server_sock, atoi(argv[optind])) != 0) {
        fatal_error("Invalid Port");
    }

    run_server(&server_sock);

    return 0;
}


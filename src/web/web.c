/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2018 by Paolo Lucente

 * web api addon is Copyright (C) 2018 by Yuri Lachin
 */
#include <stdio.h>
#include <libgen.h>
#ifdef WITH_JANSSON
#include <jansson.h>
#endif
#include "mongoose.h"
#include "pmacct.h"
#include "thread_pool.h"
#include "addr.h"
#include "web.h"

extern unsigned char *netflow_packet_mirror; /* pointer to currently processed netflow_packet */

static struct mg_serve_http_opts s_http_server_opts;
static const char *s_http_port = "8000"; /* default port for http server */

/* api endpoints handlers */
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data);
/* endpoint handlers */
static void handle_index(struct mg_connection *nc, struct http_message *hm);
static void handle_dump_config(struct mg_connection *nc, struct http_message *hm);
static void handle_pidstatus(struct mg_connection *nc, struct http_message *hm);
static void handle_stats(struct mg_connection *nc, struct http_message *hm);
static void handle_flowdump(struct mg_connection *nc, struct http_message *hm);
static void handle_sum_call(struct mg_connection *nc, struct http_message *hm); /* example from mongoose sources */

int web() {
  struct mg_mgr mgr;
  struct mg_connection *nc;
  struct mg_bind_opts bind_opts;
  int i;
  char *cp;
  const char *err_str;
#if MG_ENABLE_SSL
/* TBD */
  const char *ssl_cert = NULL;
#endif

  mg_mgr_init(&mgr, NULL);

  mgr.hexdump_file = NULL; /* "/tmp/pmacct_web.hexdump"; */

  /* customize HTTP server */
  s_http_port = "8888";
  s_http_server_opts.document_root = dirname(strdup(config.config_file));  /* Path to web root directory */
  s_http_server_opts.auth_domain = "PMACCT AUTH DOMAIN"; /* Authorization domain (domain name of this web server) */
  s_http_server_opts.global_auth_file = NULL; /* set to ".htpasswd" or leave as NULL to disable authentication */
  s_http_server_opts.per_directory_auth_file = ".htpasswd"; /* set to ".htpasswd" or leave as NULL to disable authentication */
  s_http_server_opts.enable_directory_listing = "no";  /* Set to "no" to disable directory listing. Enabled by default. */
  s_http_server_opts.url_rewrites = "no";
#if MG_ENABLE_HTTP_CGI
  s_http_server_opts.cgi_file_pattern = NULL; /*  If cgi_file_pattern is NULL, **.cgi$|**.php$ is used. */
  s_http_server_opts.cgi_interpreter = "/bin/false";
#endif
#if MG_ENABLE_SSL
/* TBD */
  ssl_cert = NULL;
#endif

  /* Set HTTP server options */
  memset(&bind_opts, 0, sizeof(bind_opts));
  bind_opts.error_string = &err_str;
#if MG_ENABLE_SSL
  if (ssl_cert != NULL) {
    bind_opts.ssl_cert = ssl_cert;
  }
#endif
  nc = mg_bind_opt(&mgr, s_http_port, ev_handler, bind_opts);
  if (nc == NULL) {
    fprintf(stderr, "ERROR (%s:%s): Error starting http server on port %s: %s\n", 
	config.name, config.type,
	s_http_port, *bind_opts.error_string);
    exit_gracefully(1);
  }

  mg_set_protocol_http_websocket(nc);
  s_http_server_opts.enable_directory_listing = "yes";

  printf("NOTICE (%s:%s): Starting http server on port %s, serving %s\n", 
	config.name, config.type,
	s_http_port, s_http_server_opts.document_root);

  for (;;) { /* main loop */
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);

  return 0;
}

/* variables to be exported away */
thread_pool_t *web_pool;

/* Functions */
void nfacctd_web_wrapper()
{
  /* initialize threads pool */
  web_pool = allocate_thread_pool(1);
  printf("web thread pool allocated\n");
  assert(web_pool);
  /* giving a kick to the WEB thread */
  send_to_pool(web_pool, web, NULL);
  printf("web sent to thread pool web_pool\n");
}


/**
  map request URLs to callbacks 
  TBD: this primitive router has to be replaced
**/ 
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  switch (ev) {
    case MG_EV_HTTP_REQUEST:
      if (mg_vcmp(&hm->uri, "/") == 0) {
        handle_index(nc, hm); /* Handle root index page request */
      } else if (mg_vcmp(&hm->uri, "/api/v1/sum") == 0) {
        handle_sum_call(nc, hm); /* Handle RESTful call */
#ifdef WITH_JANSSON
      } else if (mg_vcmp(&hm->uri, "/api/v1/config") == 0) {
        handle_dump_config(nc, hm); /* callback to dump nfacctd config */
      } else if (mg_vcmp(&hm->uri, "/api/v1/pidstatus") == 0) {
        handle_pidstatus(nc, hm); /* callback to get pids and status of a running processes */
      } else if (mg_vcmp(&hm->uri, "/api/v1/stats") == 0) {
        handle_stats(nc, hm); /* callback to get statistics as for SIGUSR1 */
      } else if (mg_vcmp(&hm->uri, "/api/v1/flow/dump") == 0) {
        handle_flowdump(nc, hm); /* callback to get a dump of flow packet sampled at time of request */
#endif
      } else if (mg_vcmp(&hm->uri, "/printcontent") == 0) {
        char buf[100] = {0};
        memcpy(buf, hm->body.p,
               sizeof(buf) - 1 < hm->body.len ? sizeof(buf) - 1 : hm->body.len);
        printf("%s\n", buf);
      } else if (mg_vcmp(&hm->uri, "/help") == 0) {
        mg_http_serve_file(nc, hm, "index.html", mg_mk_str("text/html"), mg_mk_str(""));
      } else {
        mg_serve_http(nc, hm, s_http_server_opts); /* Serve static content */
      }
      break;
    default:
      break;
  }
}


static void handle_sum_call(struct mg_connection *nc, struct http_message *hm) {
  char n1[100], n2[100];
  double result;

  /* Get form variables */
  mg_get_http_var(&hm->body, "n1", n1, sizeof(n1));
  mg_get_http_var(&hm->body, "n2", n2, sizeof(n2));

  /* Send headers */
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

  /* Compute the result and send it back as a JSON object */
  result = strtod(n1, NULL) + strtod(n2, NULL);
  mg_printf_http_chunk(nc, "{ \"result\": %lf }", result);
  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

#ifdef WITH_JANSSON
/* some of /proc/ sources to look at:
/proc/<pid>/status
/proc/<pid>/task/<pid>/children
*/
static void handle_pidstatus(struct mg_connection *nc, struct http_message *hm) {
  pid_t pid = getpid();
  json_t *obj = json_object();
  json_t *status_lines = json_array();
  json_t *children_lines = json_array();
  FILE *file;
  char filename[FILENAME_MAX + 1];
  char *line = NULL;
  size_t len = 0;
  ssize_t nread;
  char *result;

  json_object_set_new_nocheck(obj, "main_process_pid",json_integer((json_int_t)pid));

  snprintf(filename, FILENAME_MAX + 1, "/proc/%d/status", pid);
  file = fopen(filename, "r");

  json_object_set_new_nocheck(obj, "status", status_lines);

  while ((nread = getline(&line, &len, file)) != -1)
  {
    printf("Retrieved line of length %zu:\n", nread);
    printf("%s\n",line);
    json_array_append_new(status_lines, json_string(line));
  }
  free(line);
  fclose(file);

  snprintf(filename, FILENAME_MAX + 1, "/proc/%d/task/%d/children", pid, pid);
  file = fopen(filename, "r");

  json_object_set_new_nocheck(obj, "children", children_lines);

  while ((nread = getline(&line, &len, file)) != -1)
  {
    printf("Retrieved line of length %zu:\n", nread);
    printf("%s\n",line);
    json_array_append_new(children_lines, json_string(line));
  }
  free(line);
  fclose(file);

  result = json_dumps(obj,0);

  printf("JSON_DUMP_OF_PIDLIST: %s\n",json_dumps(obj, JSON_INDENT(4)|JSON_SORT_KEYS));

  /* Send headers */
/*  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");*/
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n");

  mg_printf_http_chunk(nc, "{ \"ProcessStatus\": %s }", json_dumps(obj,0));

  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

/* 
 * return JSON representation of current configuration 
*/
static void handle_dump_config(struct mg_connection *nc, struct http_message *hm) {
  int i;
  char *result = NULL;
  json_t *obj = json_object();
  json_t *ptf_table = json_array();
  json_t *pt2f_table = json_array();
  json_t *ptlf_table = json_array();
  json_t *primitive = json_array();

/* 
 * include generated code for struct configuration to json conversion
*/
#include "auto_cfg2json.h"

/* add hand-written code to convert embedded structs and arrays to json */
  json_object_set_new_nocheck(obj, "ptf", json_object());
  json_object_set_new_nocheck(json_object_get(obj,"ptf"), "num", json_integer((json_int_t)config.ptf.num));
  json_object_set_new_nocheck(json_object_get(obj,"ptf"), "table", ptf_table);
  for (i=0;i<config.ptf.num;i++)
  {
    json_t *ptt_entry = json_object();
    json_object_set_new_nocheck(ptt_entry, "neg", json_integer((json_int_t)config.ptf.table[i].neg));
    json_object_set_new_nocheck(ptt_entry, "n", json_integer((json_int_t)config.ptf.table[i].n));
    json_object_set_new_nocheck(ptt_entry, "r", json_integer((json_int_t)config.ptf.table[i].r));
    json_array_append_new(ptf_table, ptt_entry);
  }

  json_object_set_new_nocheck(obj, "pt2f", json_object());
  json_object_set_new_nocheck(json_object_get(obj,"pt2f"), "num", json_integer((json_int_t)config.pt2f.num));
  json_object_set_new_nocheck(json_object_get(obj,"pt2f"), "table", pt2f_table);
  for (i=0;i<config.ptf.num;i++)
  {
    json_t *ptt_entry = json_object();
    json_object_set_new_nocheck(ptt_entry, "neg", json_integer((json_int_t)config.pt2f.table[i].neg));
    json_object_set_new_nocheck(ptt_entry, "n", json_integer((json_int_t)config.pt2f.table[i].n));
    json_object_set_new_nocheck(ptt_entry, "r", json_integer((json_int_t)config.pt2f.table[i].r));
    json_array_append_new(pt2f_table, ptt_entry);
  }

  json_object_set_new_nocheck(obj, "ptlf", json_object());
  json_object_set_new_nocheck(json_object_get(obj,"ptlf"), "num", json_integer((json_int_t)config.ptlf.num));
  json_object_set_new_nocheck(json_object_get(obj,"ptlf"), "table", ptlf_table);
  for (i=0;i<config.ptlf.num;i++)
  {
    json_t *ptlt_entry = json_object();
    json_object_set_new_nocheck(ptlt_entry, "neg", json_integer((json_int_t)config.ptlf.table[i].neg));
    json_object_set_new_nocheck(ptlt_entry, "len", json_integer((json_int_t)config.ptlf.table[i].len));
    json_object_set_new_nocheck(ptlt_entry, "v", json_string(config.ptlf.table[i].v));
    json_array_append_new(ptlf_table, ptlt_entry);
  }

  json_object_set_new_nocheck(obj, "cpptrs", json_object()); /* struct custom_primitives_ptrs cpptrs*/
  json_object_set_new_nocheck(json_object_get(obj,"cpptrs"), "num", json_integer((json_int_t)config.cpptrs.num));
  json_object_set_new_nocheck(json_object_get(obj,"cpptrs"), "len", json_integer((json_int_t)config.cpptrs.len));
  json_object_set_new_nocheck(json_object_get(obj,"cpptrs"), "primitive", primitive);
  for (i=0;i<config.cpptrs.num;i++)
  {
    json_t *prim_entry = json_object();
    json_object_set_new_nocheck(prim_entry, "name", json_string(config.cpptrs.primitive[i].name));
    json_object_set_new_nocheck(prim_entry, "off", json_integer((json_int_t)config.cpptrs.primitive[i].off));
    json_object_set_new_nocheck(prim_entry, "ptr", json_object());
    json_array_append_new(primitive, prim_entry);
  }

/*  printf("JSON_DUMP_OF_CONFIG: %s\n",json_dumps(obj, JSON_INDENT(4)|JSON_SORT_KEYS)); */

  result = json_dumps(obj,0);

  /* Send headers */
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n");

  mg_printf_http_chunk(nc, "{ \"result\": %s \n}", result);
  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}
#endif


/* 
 * adapted from ../xflow_status.c: void print_status_table(time_t now, int buckets)
*/
static void handle_stats(struct mg_connection *nc, struct http_message *hm)
{
  time_t now  = time(NULL);;
  int buckets = XFLOW_STATUS_TABLE_SZ;

  struct xflow_status_entry *entry; 
  int idx;
  char agent_ip_address[INET6_ADDRSTRLEN];
  char collector_ip_address[INET6_ADDRSTRLEN];
  char null_ip_address[] = "0.0.0.0";

  if (!(config.acct_type == ACCT_NF || config.acct_type == ACCT_SF)) {
    mg_printf(nc, "%s", "HTTP/1.1 501 OK\r\n\r\n");
    return;
  }

  /* Send headers */
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n");

  mg_printf_http_chunk(nc, "<h2>(%s:%s): statistics</h2>\n", config.name, config.type);

  if (config.nfacctd_ip) {
    memcpy(collector_ip_address, config.nfacctd_ip, MAX(strlen(config.nfacctd_ip), INET6_ADDRSTRLEN));
  } else {
    strcpy(collector_ip_address, null_ip_address);
  }

  mg_printf_http_chunk(nc, "<html><body><pre>");

  for (idx = 0; idx < buckets; idx++) {
    entry = xflow_status_table[idx];

    bucket_cycle:
    if (entry && entry->counters.total && entry->counters.bytes) {
      addr_to_str(agent_ip_address, &entry->agent_addr);

      mg_printf_http_chunk(nc,
	"%s/%s: stats [%s:%u] agent=%s:%u time=%lu packets=%lu bytes=%lu seq_good=%u seq_jmp_fwd=%u seq_jmp_bck=%u\n",
	config.name, config.type, collector_ip_address, config.nfacctd_port,
	agent_ip_address, entry->aux1, now, entry->counters.total, entry->counters.bytes,
	entry->counters.good, entry->counters.jumps_f, entry->counters.jumps_b
      );

      if (entry->next) {
	entry = entry->next;
	goto bucket_cycle;
      }
    } 
  }

  mg_printf_http_chunk(nc,
    "<b>SUMMARY</b>:\n%s/%s: stats [%s:%u] time=%lu discarded_packets=%u\n",
	config.name, config.type, collector_ip_address, config.nfacctd_port,
	now, xflow_tot_bad_datagrams
  );

  mg_printf_http_chunk(nc, "</pre></body></html>");

  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

static void handle_index(struct mg_connection *nc, struct http_message *hm) {
  /* Send headers */
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n");

  mg_printf_http_chunk(nc, "<html><head><title>%s</title>\n<body>\n%s\n</body></html>", 
    "Web api for config.name",
    "<h1>API endpoints</h1><ul>\n"
    "<li><a href='/help'>Index start page and sample docs in external html file</a/>\n"
    "<li><a href='/api/v1/config'>Collector config</a/>\n"
    "<li><a href='/api/v1/pidstatus'>Status of running process</a/>\n"
    "<li><a href='/api/v1/stats'>Collector statistics</a/>\n"
    "<li><a href='/api/v1/flow/dump'>Dump flow packet(s)</a/>\n"
    "<li><a href='/api/v1/sum'>Demo form handler from Mongoose sources</a/>\n"
    "<ul>"
  );
  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}


/*
 * !!! very crude dump of current data in netflow_packet. Not checks are performed whether the packet is ready or not!
**/
static void handle_flowdump(struct mg_connection *nc, struct http_message *hm) {
#define HEXDUMP_SIZE 9000
  char netflow_packet_hexdump[2 * HEXDUMP_SIZE];

  /* Send headers */
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n");

  mg_hexdump(netflow_packet_mirror, HEXDUMP_SIZE, netflow_packet_hexdump, HEXDUMP_SIZE);

  mg_printf_http_chunk(nc, "\n******* PACKET SAMPLE*******\n%s\n\n", netflow_packet_hexdump);
#undef HEXDUMP_SIZE

  mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

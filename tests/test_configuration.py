"""Exercise the public configuration API without a device or network."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/pagekite_tunnel.c').read_text()
h=(root/'include/pagekite_tunnel.h').read_text().replace('#pragma once','').replace('#include "esp_err.h"','typedef int esp_err_t;')
code=r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_NO_MEM 2
#define portENTER_CRITICAL(p) ((void)0)
#define portEXIT_CRITICAL(p) ((void)0)
#define PAGEKITE_STACK_BYTES 12288
#define pdPASS 1
'''+h+r'''
static pagekite_config_t requested_config;
static int config_mux;
static void *tunnel_task;
static int notifications,creates,fail_create;
static pagekite_status_state_t status;
static void task(void *p){(void)p;}
static void set_status(pagekite_status_state_t v){status=v;}
static void xTaskNotifyGive(void *p){assert(p);notifications++;}
static int xTaskCreate(void (*fn)(void *),const char *name,unsigned stack,void *arg,int priority,void **out){
 (void)fn;(void)name;(void)arg;(void)priority;assert(stack==12288);
 if(fail_create)return 0;
 creates++;*out=(void *)1;return pdPASS;
}
'''+s[s.index('static bool valid_domain('):]+r'''
static const char *route(const char *m,const char *p){(void)m;return p;}
int main(void){
 assert(pagekite_tunnel_start(NULL)==ESP_ERR_INVALID_ARG);
 pagekite_config_t c={0};assert(pagekite_tunnel_start(&c)==ESP_OK && status==PAGEKITE_STATUS_DISABLED && !creates);
 c.enabled=true;strcpy(c.domain,"demo.pagekite.me");strcpy(c.secret,"example-only-not-a-real-secret");c.route=route;
 fail_create=1;assert(pagekite_tunnel_start(&c)==ESP_ERR_NO_MEM && !tunnel_task);
 fail_create=0;assert(pagekite_tunnel_start(&c)==ESP_OK && creates==1);
 assert(requested_config.local_port==80 && !strcmp(requested_config.domain,c.domain));
 c.domain[0]='X';assert(!strcmp(requested_config.domain,"demo.pagekite.me"));
 assert(pagekite_tunnel_start(&c)==ESP_ERR_INVALID_ARG && !notifications);
 c.domain[0]='d';strcpy(c.secret,"bad\r\nsecret");assert(pagekite_tunnel_start(&c)==ESP_ERR_INVALID_ARG);
 memset(c.secret,'a',sizeof c.secret);assert(pagekite_tunnel_start(&c)==ESP_ERR_INVALID_ARG);
 strcpy(c.secret,"replacement-example");c.route=NULL;assert(pagekite_tunnel_start(&c)==ESP_ERR_INVALID_ARG);
 c.route=route;c.local_port=8080;assert(pagekite_tunnel_start(&c)==ESP_OK && notifications==1 && creates==1);
 assert(requested_config.local_port==8080);
 memset(c.custom_domain,'a',sizeof c.custom_domain);assert(pagekite_tunnel_start(&c)==ESP_ERR_INVALID_ARG);
 c=(pagekite_config_t){0};assert(pagekite_tunnel_start(&c)==ESP_OK && notifications==2);
 assert(!requested_config.enabled && !*requested_config.secret && !*requested_config.domain);
 (void)config_mux;
 puts("PASS configuration validation, copying, default/custom port, allocation failure, reconnect and disable");
}
'''
with tempfile.TemporaryDirectory() as directory:
 p=Path(directory);(p/'test.c').write_text(code)
 subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=20)

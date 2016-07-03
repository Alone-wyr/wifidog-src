/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"

//启动一个线程，该线程会周期性的检测是否有连接的客户端已经超时了.
/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Sleep for config.checkinterval seconds... */
		//检测间隔时间...单位就是秒咯.
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);

        debug(LOG_DEBUG, "Running fw_counter()");

        fw_sync_with_authserver();
    }
}

/**
 * @brief Logout a client and report to auth server.
 *
 * This function assumes it is being called with the client lock held! This
 * function remove the client from the client list and free its memory, so
 * client is no langer valid when this method returns.
 *
 * @param client Points to the client to be logged out
 */
void
logout_client(t_client * client)
{
    t_authresponse authresponse;
    const s_config *config = config_get_config();
    fw_deny(client);
	//从client list上移除下来..
    client_list_remove(client);

    /* Advertise the logout if we have an auth server */
    if (config->auth_servers != NULL) {
        UNLOCK_CLIENT_LIST();
		//告诉服务器..我们注销掉了一个客户..因为它超时了,或者是点击了断开按钮??(类似于在上学的
		//时候，连接cmcc登录成功后跳转到页面有个disconnect按钮的页面,,退出的时候就点击它../
		//当然不按disconnect，直接关闭wifi的话..也会在一断时间内断开..
		//因此可以认为断开有2种方式，要么主动的点击disconnect，要么是超时了..(一定时间内没有数据的交互)
        auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT,
                            client->ip, client->mac, client->token,
                            client->counters.incoming, client->counters.outgoing, client->counters.incoming_delta, client->counters.outgoing_delta);

        if (authresponse.authcode == AUTH_ERROR)
            debug(LOG_WARNING, "Auth server error when reporting logout");
        LOCK_CLIENT_LIST();
    }
	//释放client结构体占用的内存.
    client_free_node(client);
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request * r)
{
    t_client *client, *tmp;
    t_authresponse auth_response;
    char *token;
    httpVar *var;
    char *urlFragment = NULL;
    s_config *config = NULL;
    t_auth_serv *auth_server = NULL;

    LOCK_CLIENT_LIST();
	//http_callback_auth函数里面会添加client到client list.
    client = client_dup(client_list_find_by_ip(r->clientAddr));

    UNLOCK_CLIENT_LIST();

    if (client == NULL) {
        debug(LOG_ERR, "authenticate_client(): Could not find client for %s", r->clientAddr);
        return;
    }

    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) {
        token = safe_strdup(var->value);
    } else {
        token = safe_strdup(client->token);
    }

    /* 
     * At this point we've released the lock while we do an HTTP request since it could
     * take multiple seconds to do and the gateway would effectively be frozen if we
     * kept the lock.
     */
     //发送认证到auth server..认证的结果会存放到 authresponse->authcode..
    auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, client->ip, client->mac, token, 0, 0, 0, 0);

    LOCK_CLIENT_LIST();

    /* can't trust the client to still exist after n seconds have passed */
    tmp = client_list_find_by_client(client);

    if (NULL == tmp) {
        debug(LOG_ERR, "authenticate_client(): Could not find client node for %s (%s)", client->ip, client->mac);
        UNLOCK_CLIENT_LIST();
        client_list_destroy(client);    /* Free the cloned client */
        free(token);
        return;
    }
	//client在上面通过dup操作...之所以要dup一个新的是因为调用auth_server_request是一个耗时的函数...
	//同时该函数会处理client结构体...因此先dup..接着释放锁..等操作完成之后上锁，还需要再次判断该client
	//是否依旧存在,(client_list_find_by_client).
    client_list_destroy(client);        /* Free the cloned client */
	//好.现在client就是指向client list的client了.
    client = tmp;

    if (strcmp(token, client->token) != 0) {
        /* If token changed, save it. */
        free(client->token);
        client->token = token;
    } else {
        free(token);
    }

    /* Prepare some variables we'll need below */
    config = config_get_config();
    auth_server = get_auth_server();
	//函数auth_server_request会设置认证码...根据认证码在来看看authentication是否成功..
    switch (auth_response.authcode) {

    case AUTH_ERROR:
        /* Error talking to central server */
        debug(LOG_ERR, "Got ERROR from central server authenticating token %s from %s at %s", client->token, client->ip,
              client->mac);
        send_http_page(r, "Error!", "Error: We did not get a valid answer from the central server");
		/*
		我擦..验证失败(ERROR/DENIED等)之后竟然不会把client从client list中给delete掉..
		不过有个线程会定时查看client list中每个client的数据情况..发现它的流量一段时间内并
		没有变化就会把它从client list掉..
		可能的原因是假设，认证失败后，客户有可能马上会再次认证吧，作为一个cache的功能..
		比如在登录页面输入的账号和密码错误..然后当然会在重新输入一次..此时在http_callback_auth
		就会查找到client list已经有这个client结构体啦..
		I suppose.
		*/
        break;

    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO,
              "Got DENIED from central server authenticating token %s from %s at %s - deleting from firewall and redirecting them to denied message",
              client->token, client->ip, client->mac);
        fw_deny(client);
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED);
		/*
		gw_message.php?message=denied作为url fragment发送到认证服务器上..
		*/
        http_send_redirect_to_auth(r, urlFragment, "Redirect to denied message");
        free(urlFragment);
        break;

    case AUTH_VALIDATION:
        /* They just got validated for X minutes to check their email */
		//仅仅是认证通过，可以允许访问几分钟而已...??
		//mark FW_MARK_PROBATION，也就是试用期的意思...
        debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
              "- adding to firewall and redirecting them to activate message", client->token, client->ip, client->mac);
        fw_allow(client, FW_MARK_PROBATION);
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
		/*
		gw_message.php?message=ativate作为url fragment发送到认证服务器上..
		*/
        http_send_redirect_to_auth(r, urlFragment, "Redirect to activate message");
        free(urlFragment);
        break;

    case AUTH_ALLOWED:
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
              "adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
        fw_allow(client, FW_MARK_KNOWN);
        served_this_session++;
        safe_asprintf(&urlFragment, "%sgw_id=%s", auth_server->authserv_portal_script_path_fragment, config->gw_id);
		/*
		portal/?gw_id=xxx作为url fragment 发送到认证服务器.
		*/
        http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
        free(urlFragment);
        break;

    case AUTH_VALIDATION_FAILED:
        /* Client had X minutes to validate account by email and didn't = too late */
        debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
              "- redirecting them to failed_validation message", client->token, client->ip, client->mac);
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to failed validation message");
        free(urlFragment);
        break;

    default:
        debug(LOG_WARNING,
              "I don't know what the validation code %d means for token %s from %s at %s - sending error message",
              auth_response.authcode, client->token, client->ip, client->mac);
        send_http_page(r, "Internal Error", "We can not validate your request at this time");
        break;

    }

    UNLOCK_CLIENT_LIST();
    return;
}

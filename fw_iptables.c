/* vim: set et ts=4 sts=4 sw=4 : */
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
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(const char *format, ...);
static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
	//确实看起来很odd(奇怪的)....可以认为是%s啦...然后下面safe_asprintf调用使用config->gw_interface来替换这个%s.
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    safe_asprintf(&buffer, *input, config->gw_interface);

    free(*input);
    *input = buffer;
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(const char *table, const char *chain, const t_firewall_rule * rule)
{
    char command[MAX_BUF], *mode;

    memset(command, 0, MAX_BUF);
    mode = NULL;

    switch (rule->target) {
    case TARGET_DROP:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("DROP");
        break;
    case TARGET_REJECT:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("REJECT");
        break;
    case TARGET_ACCEPT:
        mode = safe_strdup("ACCEPT");
        break;
    case TARGET_LOG:
        mode = safe_strdup("LOG");
        break;
    case TARGET_ULOG:
        mode = safe_strdup("ULOG");
        break;
    }

    snprintf(command, sizeof(command), "-t %s -A %s ", table, chain);
    if (rule->mask != NULL) {
        if (rule->mask_is_ipset) {
            snprintf((command + strlen(command)), (sizeof(command) -
                                                   strlen(command)), "-m set --match-set %s dst ", rule->mask);
        } else {
            snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-d %s ", rule->mask);
        }
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-j %s", mode);

    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return (safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
 #if 0
 一条规则的结构体定义如下......
 typedef struct _firewall_rule_t {
    t_firewall_target target;   /**< @brief t_firewall_target */
    char *protocol;             /**< @brief tcp, udp, etc ... */
    char *port;                 /**< @brief Port to block/allow */
    char *mask;                 /**< @brief Mask for the rule *destination* */
    int mask_is_ipset; /**< @brief *destination* is ipset  */
    struct _firewall_rule_t *next;
} t_firewall_rule;
#endif
static void
iptables_load_ruleset(const char *table, const char *ruleset, const char *chain)
{
    t_firewall_rule *rule;
    char *cmd;

    debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

    for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
        cmd = iptables_compile(table, chain, rule);
        if (cmd != NULL) {
            debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
            iptables_do_command(cmd);
        }
        free(cmd);
    }

    debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    const s_config *config;
    t_auth_serv *auth_server;

    config = config_get_config();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		//last_ip有效的情况下..该服务器才是有作用的...因为是解析hostname得到的ip地址存放的地方..
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
			//因此这里是接受所有有效认证服务器的访问..
			//只要数据包-d目的ip地址指定为认证服务器...那它的动作就是accept接受的.
            iptables_do_command("-t filter -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
        }
    }

}

/** Initialize the firewall rules
*/
int
iptables_fw_init(void)
{
    const s_config *config;
    char *ext_interface = NULL;
    int gw_port = 0;
    t_trusted_mac *p;
    int proxy_port;
    fw_quiet = 0;
									//获取name = "auth-is-down"的规则集合.
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;

    LOCK_CONFIG();
    config = config_get_config();
    gw_port = config->gw_port;
    if (config->external_interface) {
        ext_interface = safe_strdup(config->external_interface);
    } else {
        ext_interface = get_ext_iface();
    }

    if (ext_interface == NULL) {
        UNLOCK_CONFIG();
        debug(LOG_ERR, "FATAL: no external interface");
        return 0;
    }
    /*
     *
     * Everything in the MANGLE table
     *
     */

    /* Create new chains */
	//创建新的链.
									//"WiFiDog_$ID$_Trusted"
    iptables_do_command("-t mangle -N " CHAIN_TRUSTED);
									//"WiFiDog_$ID$_Outgoing"
    iptables_do_command("-t mangle -N " CHAIN_OUTGOING);
									//"WiFiDog_$ID$_Incoming"
    iptables_do_command("-t mangle -N " CHAIN_INCOMING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
	//把新创建的链
			//-I -> insert  1:插入到第一条规则位置吗? -i->input -j
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_OUTGOING, config->gw_interface);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_TRUSTED, config->gw_interface);     //this rule will be inserted before the prior one
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_AUTH_IS_DOWN, config->gw_interface);    //this rule must be last in the chain
    iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " CHAIN_INCOMING, config->gw_interface);
		//信任的mac地址列表...这个链是CHAIN_TRUSTED，它刚好是在mangle 的 PREROUTING的
		//因此当数据经过路由器会通过这个CHAIN_TRUSTED链...
    for (p = config->trustedmaclist; p != NULL; p = p->next)
        iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->mac,
                            FW_MARK_KNOWN);
	/*
	上面的fw规则总结就是,数据包经过路由器发送到互联网:
		进来会先通过mangle的PREROUTING链，然后进入到trusted链，该链记录着一些白名单...
	匹配--mac-source，如果匹配则标记为2..接下去会进入到outgoing的链，控制要输出的数据包吧..我猜测.
	对于路由器接受到数据发送到网关接口的数据包:
		在postrouting hook点设置的incoming链.
	*/
    /*
     *
     * Everything in the NAT table
     *
     */

    /* Create new chains */
    iptables_do_command("-t nat -N " CHAIN_OUTGOING);
    iptables_do_command("-t nat -N " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -N " CHAIN_GLOBAL);
    iptables_do_command("-t nat -N " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
	//着个规则类似于mengle表中也有...那就是先进入到mangle的outgoing链..然后在nat的outgoing链.
    iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_OUTGOING, config->gw_interface);
	//在nat的outgoing链中添加规则..如果目的地址是网关..那就是发送给路由器的而不是发送到互联网的..
	//这样的数据包发送到router链上..
    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -d %s -j " CHAIN_TO_ROUTER, config->gw_address);
	//发送给路由器的任何数据包执行的动作就是accept...
    iptables_do_command("-t nat -A " CHAIN_TO_ROUTER " -j ACCEPT");
	//如果没有进入到router的链上...那就是数据包不是发送给router的..那就是发送到互联网的..此时数据包会走到
	//internet的链上.
    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_TO_INTERNET);

    if ((proxy_port = config_get_config()->proxy_port) != 0) {
        debug(LOG_DEBUG, "Proxy port set, setting proxy rule");
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN,
                            proxy_port);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_PROBATION,
                            proxy_port);
    }
	//来到internet的链表都是确定要发送到互联网的了...
	//但是我们前面有说过会设置白名单..它会设置数据包的mark值..因此--mark就是来判断数据包的mark值..
	//如果是FW_MARK_KNOWN，就accept放行..FW_MARK_PROBATION是作为代理端口(我还没有分析).
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
	//如果不是要放行的数据包...那么就走到unknown的链上了...不知道这个数据包是要干啥子的!!!unknown...
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);
	//对于不知道要干嘛的数据包..先到authservers链去认领一下..然后在到global认领一下...
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_GLOBAL);
    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t nat -A " CHAIN_AUTH_IS_DOWN " -m mark --mark 0x%u -j ACCEPT", FW_MARK_AUTH_IS_DOWN);
    }
	//那如果authservers和global都认领不了...且如果数据包的目的端口是80..那就使用DNAT转化一下访问的端口为gw_port..
	//这里需要特别注意的是，因为数据包是发送到互联网的.而不是发送到路由器的..那么此时数据包的目的地址，目的MAC地址，
	//设置都是网关的...因此转换后相当于在访问路由器gw_port端口的应用程序了...也就是wifidog作为服务端的接口.
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);

    /*
     *
     * Everything in the FILTER table
     *
     */

    /* Create new chains */
    iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -N " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -N " CHAIN_LOCKED);
    iptables_do_command("-t filter -N " CHAIN_GLOBAL);
    iptables_do_command("-t filter -N " CHAIN_VALIDATE);
    iptables_do_command("-t filter -N " CHAIN_KNOWN);
    iptables_do_command("-t filter -N " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */

    /* Insert at the beginning */
	//对于进入端口为网关的数据包经过了路由后到了forward的链...此时会进入到internet链上..
    iptables_do_command("-t filter -I FORWARD -i %s -j " CHAIN_TO_INTERNET, config->gw_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");

    /* XXX: Why this? it means that connections setup after authentication
       stay open even after the connection is done... 
       iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT"); */

    //Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
    //iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

    /* TCPMSS rule for PPPoE */
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET
                        " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_AUTHSERVERS);
	//往nat表和filter表的authservers的链上添加放行访问认证服务器的规则..
    iptables_fw_set_authservers();

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_LOCKED, FW_MARK_LOCKED);
    iptables_load_ruleset("filter", FWRULESET_LOCKED_USERS, CHAIN_LOCKED);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_GLOBAL);
    iptables_load_ruleset("filter", FWRULESET_GLOBAL, CHAIN_GLOBAL);
    iptables_load_ruleset("nat", FWRULESET_GLOBAL, CHAIN_GLOBAL);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_VALIDATE, FW_MARK_PROBATION);
    iptables_load_ruleset("filter", FWRULESET_VALIDATING_USERS, CHAIN_VALIDATE);
	//标记为known的为放行的白名单...检测到是放行白名单设备的数据包...执行known链...
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_KNOWN, FW_MARK_KNOWN);
    iptables_load_ruleset("filter", FWRULESET_KNOWN_USERS, CHAIN_KNOWN);

    if (got_authdown_ruleset) {
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_AUTH_IS_DOWN,
                            FW_MARK_AUTH_IS_DOWN);
        iptables_load_ruleset("filter", FWRULESET_AUTH_IS_DOWN, CHAIN_AUTH_IS_DOWN);
    }
	//来到这里代表数据包都是无人认领的...就是一些unknown的数据包咯..
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);
    iptables_load_ruleset("filter", FWRULESET_UNKNOWN_USERS, CHAIN_UNKNOWN);
	//那就会被拒绝....后面的reject with...还不明白..是返回一个信息给发送数据包的主机吗..为icmp类型的包，指示为端口不可到达..
	//因为是希望获取80端口进行认证的..在没有认证之前访问其他端口都会在这里被抛弃..?
    iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

    UNLOCK_CONFIG();

    free(ext_interface);
    return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    debug(LOG_DEBUG, "Destroying our iptables entries");

    /*
     *
     * Everything in the MANGLE table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_AUTH_IS_DOWN);
    iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
    iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -F " CHAIN_INCOMING);
    iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -X " CHAIN_INCOMING);

    /*
     *
     * Everything in the NAT table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the NAT table");
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -F " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    iptables_do_command("-t nat -F " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -X " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);
    iptables_do_command("-t nat -X " CHAIN_UNKNOWN);

    /*
     *
     * Everything in the FILTER table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the FILTER table");
    iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -F " CHAIN_LOCKED);
    iptables_do_command("-t filter -F " CHAIN_GLOBAL);
    iptables_do_command("-t filter -F " CHAIN_VALIDATE);
    iptables_do_command("-t filter -F " CHAIN_KNOWN);
    iptables_do_command("-t filter -F " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -X " CHAIN_LOCKED);
    iptables_do_command("-t filter -X " CHAIN_GLOBAL);
    iptables_do_command("-t filter -X " CHAIN_VALIDATE);
    iptables_do_command("-t filter -X " CHAIN_KNOWN);
    iptables_do_command("-t filter -X " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -X " CHAIN_AUTH_IS_DOWN);

    return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention)
{
    FILE *p = NULL;
    char *command = NULL;
    char *command2 = NULL;
    char line[MAX_BUF];
    char rulenum[10];
    char *victim = safe_strdup(mention);
    int deleted = 0;

    iptables_insert_gateway_id(&victim);

    debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);
		//显示某个表内的某个链的规则...在第一列显示出行号.
    safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
    iptables_insert_gateway_id(&command);
	
		//popen打开命令..返回的结果可以直接fgets读取咯...
    if ((p = popen(command, "r"))) {
        /* Skip first 2 lines */
        while (!feof(p) && fgetc(p) != '\n') ;
        while (!feof(p) && fgetc(p) != '\n') ;
        /* Loop over entries */
	//循环所有的条目.
        while (fgets(line, sizeof(line), p)) {
            /* Look for victim 牺牲品..受害人...*/
            if (strstr(line, victim)) {
                /* Found victim - Get the rule number into rulenum */
				//%9[0-9]的意思是查找0-9..如果遇到不是0-9就返回..同时最多只能读取长度9
                if (sscanf(line, "%9[0-9]", rulenum) == 1) {
                    /* Delete the rule: */
                    debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain,
                          victim);
                    safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
                    iptables_do_command(command2);
                    free(command2);
                    deleted = 1;
                    /* Do not keep looping - the captured rulenums will no longer be accurate */
                    break;
                }
            }
        }
        pclose(p);
    }

    free(command);
    free(victim);

    if (deleted) {
        /* Recurse just in case there are more in the same table+chain */
        iptables_fw_destroy_mention(table, chain, mention);
    }

    return (deleted);
}

/** Set if a specific client has access through the firewall */
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

int
iptables_fw_access_host(fw_access_t type, const char *host)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    case FW_ACCESS_DENY:
        iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

/** Set a mark when auth server is not reachable */
int
iptables_fw_auth_unreachable(int tag)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -A " CHAIN_AUTH_IS_DOWN " -j MARK --set-mark 0x%u", tag);
    else
        return 1;
}

/** Remove mark when auth server is reachable again */
int
iptables_fw_auth_reachable(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    else
        return 1;
}

/** Update the counters of all the clients in the client list */
/*
iptables  -v -n -x -L 显示的结果如下格式:(比如POSTROUTING链来说...
Chain POSTROUTING (policy ACCEPT 2569 packets, 2681K bytes)
 pkts bytes target     prot opt in     out     source               destination
 5139 5373K L7POSTROUTING  all  --  *      *       0.0.0.0/0            0.0.0.0/0

 因此要获取一个规则的详细信息..首先要略过前2行...
 %*s     %llu    %*s     %*s    %*s    %*s %*s %15[0-9.]       %*s             %*s %*s %*s %*s %*s
 pkts    bytes  target    prot     opt   in     out    source     destination
 ???
 */
int
iptables_fw_counters_update(void)
{
    FILE *output;
    char *script, ip[16], rc;
    unsigned long long int counter;
    t_client *p1;
    struct in_addr tempaddr;

    /* Look for outgoing traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
        //rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
				//在checkinterval的期间..有流量的产生..都会更新一些统计值..同时也有用last_updated来标记统计的时刻.
				//我猜想..假设一个客户直接关闭wifi后..wifidog并不知道..就是通过查看checkinterval期间来查看是否有流量在传输..
				//如果有流量传输更新last_updated,,代表这个时间点之前client还是在线的
				//但是一旦没有流量产生..因此它的last_updated就不会更新啦.在该函数外面有个地方会检测updated + value的值..
				//也就是value的时间内没有流量产生，那就注销该设备..(可能是client关闭了和wifi的连接吧).
				//client不会一直没有流量产生的..wifidog会间隔性的去ping客户端..那应该会有回复..之间其实有小数据的来往.
                if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
					//history只有在restart方式重启wifidog的时候有用..这时候history记录没有restart时候的流量值..
					//而delta就是restart之后重新开始计算的流量值...outgoing是总的流量值..
					//因此outgoing - history也就是此期间的流量值了吧...(我好奇..它不是就是delta吗?)
                    p1->counters.outgoing_delta = p1->counters.outgoing_history + counter - p1->counters.outgoing;
					//total..一共访问的流量值.
                    p1->counters.outgoing = p1->counters.outgoing_history + counter;
					//最后一次更新流量统计的时间..
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Outgoing traffic %llu bytes, updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip,
                          counter, p1->counters.outgoing, p1->counters.last_updated);
                }
            } else {
            	//在iptables里面查看到记录..但是在client list里面却没有查找到...
            	//很有可能是wifi dog的一个bug吧..(crashed).
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
				//删掉iptables里面该ip地址的规则。
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    /* Look for incoming traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_INCOMING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
                    p1->counters.incoming_delta = p1->counters.incoming_history + counter - p1->counters.incoming;
                    p1->counters.incoming = p1->counters.incoming_history + counter;
                    debug(LOG_DEBUG, "%s - Incoming traffic %llu bytes, Updated counter.incoming to %llu bytes", ip, counter, p1->counters.incoming);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    return 1;
}

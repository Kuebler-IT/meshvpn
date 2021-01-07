/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_CONFIG
#define H_CONFIG

#include "app.h"
#include "globals.h"

void throwError(char *msg) {
	if(msg != NULL) printf("error: %s\n",msg);
	exit(1);
}

int parseConfigInt(char *str) {
	int n = atoi(str);
	if(n < 0) return -1;
	return n;
}

int parseConfigBoolean(char *str) {
	if(strncmp(str,"true",4) == 0) {
		return 1;
	}
	else if(strncmp(str,"1",1) == 0) {
		return 1;
	}
	else if(strncmp(str,"yes",3) == 0) {
		return 1;
	}
	else if(strncmp(str,"false",5) == 0) {
		return 0;
	}
	else if(strncmp(str,"0",1) == 0) {
		return 0;
	}
	else if(strncmp(str,"no",2) == 0) {
		return 0;
	}
	else {
		return -1;
	}
}

int parseConfigIsEOLChar(char c) {
	switch(c) {
		case '#':
		case ';':
		case '\0':
		case '\r':
			return 1;
		default:
			return 0;
	}
}

int parseConfigLineCheckCommand(char *line, int linelen, const char *cmd, int *vpos) {
	int cmdlen = strlen(cmd);
	if(!(linelen >= cmdlen)) {
		return 0;
	}

	if(strncmp(line,cmd,cmdlen) != 0) {
		return 0;
	}

	if(parseConfigIsEOLChar(line[cmdlen])) {
		*vpos = cmdlen;
		return 1;
	} else if(isWhitespaceChar(line[cmdlen])) {
		*vpos = cmdlen;
		while(((*vpos)+1) < linelen) {
			if(!isWhitespaceChar(line[*vpos])) {
				break;
			}

			*vpos = (*vpos)+1;
		}
		return 1;
	} else {
		return 0;
	}
}

int parseConfigLine(char *line, int len, struct s_initconfig *cs) {
	int vpos,a;
	if(!(len > 0)) {
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"echo",&vpos)) {
		printf("%s\n",&line[vpos]);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"local",&vpos)) {
		strncpy(cs->sourceip,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"port",&vpos)) {
		strncpy(cs->sourceport,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"user",&vpos)) {
		strncpy(cs->userstr,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"group",&vpos)) {
		strncpy(cs->groupstr,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line, len, "pidfile", &vpos)) {
		strncpy(cs->pidfile, &line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		cs->enablepidfile = 1;
		return 1;
	}
    else if(parseConfigLineCheckCommand(line, len, "privatekey", &vpos)) {
        strncpy(cs->privatekey, &line[vpos], CONFPARSER_NAMEBUF_SIZE+1);
        return 1;
    }
	else if(parseConfigLineCheckCommand(line,len,"chroot",&vpos)) {
		strncpy(cs->chrootstr,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"networkname",&vpos)) {
		strncpy(cs->networkname,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"interface",&vpos)) {
		strncpy(cs->tapname,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"ifconfig4",&vpos)) {
		strncpy(cs->ifconfig4,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"ifconfig6",&vpos)) {
		strncpy(cs->ifconfig6,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"upcmd",&vpos)) {
		strncpy(cs->upcmd,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"initpeers",&vpos)) {
        cs->initpeers[cs->initpeerscount] = malloc(sizeof(char) * (CONFPARSER_NAMEBUF_SIZE+1));
		strncpy(cs->initpeers[cs->initpeerscount],&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
        cs->initpeerscount++;
        debug("detected new init peers");

		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"engine",&vpos)) {
		strncpy(cs->engines,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"psk",&vpos)) {
		strncpy(cs->password,&line[vpos],CONFPARSER_NAMEBUF_SIZE+1);
		cs->password_len = strlen(cs->password);
		return 1;
	}
	else if(parseConfigLineCheckCommand(line,len,"enableconsole",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableconsole = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enableseccomp",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableseccomp = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"forceseccomp",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->forceseccomp = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enableprivdrop",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableprivdrop = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enabletunneling",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableeth = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enablendpcache",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enablendpcache = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enablevirtserv",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enablevirtserv = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enablerelay",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enablerelay = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enableipv4",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableipv4 = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enableipv6",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enableipv6 = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enablenat64clat",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->enablenat64clat = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line, len, "daemonize", &vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		} else {
			cs->daemonize = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"enablesyslog",&vpos)) {
		if((a = parseConfigBoolean(&line[vpos])) < 0) {
			return -1;
		} else {
			cs->enablesyslog = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"sockmark",&vpos)) {
		if((a = parseConfigInt(&line[vpos])) < 0) {
			return -1;
		}
		else {
			cs->sockmark = a;
			return 1;
		}
	}
	else if(parseConfigLineCheckCommand(line,len,"endconfig",&vpos)) {
		return 0;
	}
	else {
		return -1;
	}
}

void parseConfigFile(int fd, struct s_initconfig *cs) {
	char line[CONFPARSER_LINEBUF_SIZE+1];
	char c;
	int linepos = 0;
	int linectr = 0;
	int waiteol = 0;
	int rc;
	int readlen;

    strcpy(cs->tapname,"");
    strcpy(cs->ifconfig4,"");
    strcpy(cs->ifconfig6,"");
    strcpy(cs->upcmd,"");
    strcpy(cs->sourceip,"");
    strcpy(cs->sourceport,"");
    strcpy(cs->userstr,"");
    strcpy(cs->groupstr,"");
    strcpy(cs->chrootstr,"");
    strcpy(cs->networkname,"PUBLIC_MESH");
    strcpy(cs->engines,"");
    strcpy(cs->pidfile, "");
    strcpy(cs->privatekey, "/var/run/meshvpn.pem");

    cs->password_len = 0;
    cs->enablepidfile = 0;
    cs->enableeth = 1;
    cs->enablendpcache = 0;
    cs->enablevirtserv = 0;
    cs->enablerelay = 0;
    cs->enableindirect = 0;
    cs->enableconsole = 0;
    cs->enableseccomp = 0;
    cs->forceseccomp = 0;
    cs->daemonize = 0;
    cs->enableprivdrop = 1;
    cs->enableipv4 = 1;
    cs->enableipv6 = 1;
    cs->enablenat64clat = 0;
    cs->enablesyslog = 0;
    cs->sockmark = 0;
    cs->enablepidfile = 0;
    cs->initpeerscount = 0;

	do {
		readlen = read(fd,&c,1);
		if(!(readlen > 0)) {
			c = '\n';
		}
		if(c == '\n') {
			linectr++;
			while(linepos > 0) {
				if(isWhitespaceChar(line[linepos-1])) {
					linepos--;
				}
				else {
					break;
				}
			}
			line[linepos] = '\0';
			rc = parseConfigLine(line,linepos,cs);
			if(rc < 0) {
				printf("error: config file parse error at line %d!\n", linectr);
				throwError(NULL);
			}
			if(rc == 0) break;
			linepos = 0;
			waiteol = 0;
		}
		else {
			if((!waiteol) && (!(linepos == 0 && isWhitespaceChar(c)))) {
				if(parseConfigIsEOLChar(c)) {
					line[linepos] = '\0';
					waiteol = 1;
				}
				else {
					if(linepos < (CONFPARSER_LINEBUF_SIZE)) {
						line[linepos] = c;
						linepos++;
					}
					else {
						line[linepos] = '\0';
						waiteol = 1;
					}
				}
			}
		}
	}
	while(readlen > 0);
}

#endif

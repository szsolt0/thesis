// Landlock example: The program should only be able to access the 'a.txt' file.
//
// WARNING: This is almost a perfect copy of this:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/landlock/sandboxer.c
//
// The only modifications are to make it "C++ friendly"

#include <errno.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stddef.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "raw_syscall.h"

// --- raw syscall wrappers, simplified ---

static inline
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, const size_t size, const __u32 flags) noexcept
{
	return raw_syscall3<int>(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline
int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type, const void *rule_attr, const __u32 flags) noexcept
{
	return raw_syscall4<int>(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline
int landlock_restrict_self(const int ruleset_fd, const __u32 flags) noexcept
{
	return raw_syscall2<int>(__NR_landlock_restrict_self, ruleset_fd, flags);
}

// --- simple FS access ---
constexpr auto ACCESS_FILE = (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);

int main()
{
	int err = 0;

	raw_syscall5<int>(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	struct landlock_ruleset_attr ruleset_attr {};
	ruleset_attr.handled_access_fs = ACCESS_FILE;

	int ruleset_fd = landlock_create_ruleset(&ruleset_attr,sizeof(ruleset_attr), 0);

	if (ruleset_fd < 0) {
		std::cerr << "Failed to create ruleset\n";
		return 1;
	}

	// --- Allow access to a.txt ---
	struct landlock_path_beneath_attr rule_a {};
	rule_a.allowed_access = ACCESS_FILE;
	rule_a.parent_fd = open("a.txt", O_PATH | O_CLOEXEC);
	if (rule_a.parent_fd < 0) {
		perror("Failed to open a.txt");
		return 1;
	}
	if ((err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule_a, 0))) {
		std::cout << "Failed to add rule for a.txt: " << strerror(-err) << '\n';
		return 1;
	}
	close(rule_a.parent_fd);

	// --- Apply the ruleset ---
	if ((err = landlock_restrict_self(ruleset_fd, 0))) {
		std::cerr << "Failed to enforce ruleset:" << strerror(-err) << '\n';
		return 1;
	}
	close(ruleset_fd);

	// --- Test access ---
	std::cout << "Trying to open a.txt (should succeed)…\n";
	int fd = open("a.txt", O_RDONLY);
	if (fd < 0) {
		perror("failed to open a.txt");
	} else {
		std::cout << "Success!\n";
		//close(fd);
	}

	std::cout << "Trying to open b.txt (should fail)…\n";
	fd = open("b.txt", O_RDONLY);
	if (fd < 0) {
		perror("failed to open b.txt");
	} else {
		std::cout << "Unexpected success!\n";
		//close(fd);
	}

	exit_group(0);
}

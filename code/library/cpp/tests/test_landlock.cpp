#include <gtest/gtest.h>
#include <mylib/landlock.h>
#include <mylib/no_new_privs.h>

#include <sys/mman.h>

using namespace mylib;

TEST(Landlock, Basic) {
	EXPECT_TRUE(set_no_new_privs());

	auto lk = LandlockRuleSet::init();
	EXPECT_TRUE(lk);

	EXPECT_TRUE(lk->add_rule("/etc", LandlockAccess::Read));
	EXPECT_TRUE(lk->apply());
}

TEST(Landlock, Allow) {
	mkdir("test_folder", 0666);
	mkdir("test_folder/sub", 0666);
	creat("test_folder/a.txt", 0666);
	creat("test_folder/sub/a.txt", 0666);

	EXPECT_TRUE(set_no_new_privs());

	auto lk = LandlockRuleSet::init();
	EXPECT_TRUE(lk);

	EXPECT_TRUE(lk->add_rule("/etc", LandlockAccess::Read));
	EXPECT_TRUE(lk->add_rule("test_folder", LandlockAccess::ReadWrite));
	EXPECT_TRUE(lk->apply());

	auto fd1 = detail::sys_open("/etc/passwd", O_RDONLY|O_CLOEXEC, 0);
	EXPECT_TRUE(fd1 > 0);

	auto fd2 = detail::sys_open("test_folder/a.txt", O_RDWR|O_CLOEXEC, 0);
	EXPECT_TRUE(fd2 > 0);

	auto fd3 = detail::sys_open("test_folder/sub/a.txt", O_RDWR|O_CLOEXEC, 0);
	EXPECT_TRUE(fd3 > 0);

	auto fd4 = detail::sys_open("/dev", O_PATH|O_CLOEXEC, 0);
	EXPECT_FALSE(fd4 > 0);
}

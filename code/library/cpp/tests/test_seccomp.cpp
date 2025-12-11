#include <gtest/gtest.h>
#include <mylib/seccomp.h>
#include <mylib/no_new_privs.h>

#include <sys/mman.h>

using namespace mylib;

TEST(SeccompBetterStrict, StrictMode) {
	EXPECT_TRUE(set_no_new_privs());
	EXPECT_TRUE(seccomp_better_strict());

	// normal write should work
	detail::sys_write(2, "test\n", 5);

	// as well as writev
	struct iovec iov[] = {
		detail::make_iovec("Hello, "),
		detail::make_iovec("World!\n"),
	};
	detail::sys_writev(2, iov, std::size(iov));
}

TEST(SeccompBetterStrict, After) {
	detail::sys_mmap(nullptr, 1024, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

TEST(SeccompBetterStrict, Die) {
	EXPECT_DEATH({
		set_no_new_privs();
		seccomp_better_strict();
		detail::sys_mmap(nullptr, 1024, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	}, "");
}

TEST(SeccompBuilder, Build) {
	auto builder = SeccompBuilder::init();
	EXPECT_TRUE(builder) << "init builder failed: " << builder.error();

	// adding new rules should work
	EXPECT_TRUE(builder->allow("io")) << "allow rule failed";

	// adding non-existing rules should NOT work
	EXPECT_FALSE(builder->allow("jdijdsiojiodsj")) << "bad allow rule succeed";

	// building the rule should work
	auto rule = builder->build();
	EXPECT_TRUE(rule) << "building failed";
}

TEST(SeccompBuilder, Apply) {
	auto builder = SeccompBuilder::init();
	EXPECT_TRUE(builder) << "init builder failed: " << builder.error();

	// adding new rules should work
	EXPECT_TRUE(builder->allow("io")) << "allow rule failed";

	// adding non-existing rules should NOT work
	EXPECT_FALSE(builder->allow("jdijdsiojiodsj")) << "bad allow rule succeed";

	// building the rule should work
	auto rule = builder->build();
	EXPECT_TRUE(rule) << "building failed";

	set_no_new_privs();

	auto res = rule->view().apply();
	EXPECT_TRUE(res) << "rule applying failed: " << res.error();
}

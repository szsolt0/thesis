#include <gtest/gtest.h>
#include <mylib/seccomp.h>
#include <mylib/no_new_privs.h>

#include <sys/mman.h>

using namespace mylib;

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

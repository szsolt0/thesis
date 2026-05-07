#include <gtest/gtest.h>

#include <mylib/seccomp.h>
#include <mylib/no_new_privs.h>

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

using namespace mylib;

TEST(SeccompBuilder, InitSucceeds)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();
}

TEST(SeccompBuilder, InitNoDefaultsSucceeds)
{
    auto builder = SeccompBuilder::init_no_defaults();

    ASSERT_TRUE(builder) << "init_no_defaults builder failed: "
                         << builder.error();
}

TEST(SeccompBuilder, AllowsExistingCategory)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    auto res = builder->allow("io");

    EXPECT_TRUE(res) << "allow(\"io\") failed: " << res.error();
}

TEST(SeccompBuilder, RejectsUnknownCategory)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    auto res = builder->allow("definitely_not_a_real_category");

    ASSERT_FALSE(res);
    EXPECT_EQ(res.error(), ENOENT);
}

TEST(SeccompBuilder, BuildSucceedsAfterAddingCategories)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    ASSERT_TRUE(builder->allow("io"));
    ASSERT_TRUE(builder->allow("file_system"));

    auto rule = builder->build();

    EXPECT_TRUE(rule) << "building failed: " << rule.error();
}

TEST(SeccompBuilder, CannotAllowAfterBuild)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    auto rule = builder->build();
    ASSERT_TRUE(rule) << "building failed: " << rule.error();

    auto res = builder->allow("io");

    ASSERT_FALSE(res);
    EXPECT_EQ(res.error(), EALREADY);
}

TEST(SeccompBuilder, BuildCanBeCalledMoreThanOnce)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    auto rule1 = builder->build();
    ASSERT_TRUE(rule1) << "first build failed: " << rule1.error();

    auto rule2 = builder->build();
    EXPECT_TRUE(rule2) << "second build failed: " << rule2.error();
}

TEST(SeccompBuilder, ApplyBasicIoFilterSucceeds)
{
    auto builder = SeccompBuilder::init();

    ASSERT_TRUE(builder) << "init builder failed: " << builder.error();

    ASSERT_TRUE(builder->allow("io"));

    auto rule = builder->build();
    ASSERT_TRUE(rule) << "building failed: " << rule.error();

    auto nnp = set_no_new_privs();
    ASSERT_TRUE(nnp) << "set_no_new_privs failed: " << nnp.error();

    auto res = rule->view().apply();

    EXPECT_TRUE(res) << "rule applying failed: " << res.error();
}

TEST(SeccompBuilderDeathTest, DisallowedSyscallKillsProcess)
{
    ASSERT_DEATH(
        {
            auto nnp = set_no_new_privs();
            if (!nnp) {
                std::exit(1);
            }

            auto builder = SeccompBuilder::init_no_defaults();
            if (!builder) {
                std::exit(1);
            }

            /*
             * Csak a legszükségesebb kategóriákat engedjük.
             * A file_system kategóriát szándékosan nem adjuk hozzá.
             */
            if (!builder->allow("io")) {
                std::exit(1);
            }

            auto rule = builder->build();
            if (!rule) {
                std::exit(1);
            }

            auto applied = rule->view().apply();
            if (!applied) {
                std::exit(1);
            }

            /*
             * Ha az openat nincs engedélyezve, akkor ennek a hívásnak
             * a seccomp szűrő miatt meg kell ölnie a folyamatot.
             */
            int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);

            if (fd >= 0) {
                close(fd);
            }

            std::exit(0);
        },
        ""
    );
}

TEST(SeccompBuilderDeathTest, AllowedWriteDoesNotKillProcess)
{
    ASSERT_EXIT(
        {
            auto nnp = set_no_new_privs();
            if (!nnp) {
                std::exit(1);
            }

            auto builder = SeccompBuilder::init();
            if (!builder) {
                std::exit(1);
            }

            if (!builder->allow("io")) {
                std::exit(1);
            }

            auto rule = builder->build();
            if (!rule) {
                std::exit(1);
            }

            auto applied = rule->view().apply();
            if (!applied) {
                std::exit(1);
            }

            char const msg[] = "seccomp write test\n";
            ssize_t ret = write(STDOUT_FILENO, msg, sizeof(msg) - 1);

            if (ret < 0) {
                std::exit(1);
            }

            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );
}

TEST(SeccompBuilderDeathTest, AllowedFileSystemOpenDoesNotKillProcess)
{
    ASSERT_EXIT(
        {
            auto nnp = set_no_new_privs();
            if (!nnp) {
                std::exit(1);
            }

            auto builder = SeccompBuilder::init();
            if (!builder) {
                std::exit(1);
            }

            if (!builder->allow("io")) {
                std::exit(1);
            }

            if (!builder->allow("file_system")) {
                std::exit(1);
            }

            auto rule = builder->build();
            if (!rule) {
                std::exit(1);
            }

            auto applied = rule->view().apply();
            if (!applied) {
                std::exit(1);
            }

            int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);

            if (fd < 0) {
                std::exit(1);
            }

            close(fd);
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );
}

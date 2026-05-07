#include <gtest/gtest.h>

#include <mylib/landlock.h>
#include <mylib/no_new_privs.h>
#include <mylib/detail/common_syscall.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

using namespace mylib;

namespace {

std::filesystem::path make_test_root()
{
    auto root = std::filesystem::temp_directory_path()
              / ("mylib_landlock_test_" + std::to_string(::getpid()));

    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    return root;
}

void write_file(std::filesystem::path const& path, std::string const& content)
{
    std::ofstream file(path, std::ios::binary);
    ASSERT_TRUE(file) << "failed to create file: " << path;
    file << content;
}

void setup_landlock_tree(std::filesystem::path const& root)
{
    std::filesystem::create_directories(root / "allowed" / "sub");
    std::filesystem::create_directories(root / "secret");

    write_file(root / "allowed" / "a.txt", "allowed\n");
    write_file(root / "allowed" / "sub" / "nested.txt", "nested\n");
    write_file(root / "secret" / "secret.txt", "secret\n");
}

[[noreturn]] void exit_if_failed(std::expected<void, int>&& result)
{
    if (!result) {
        std::exit(result.error());
    }

    std::exit(0);
}

template <class T>
T unwrap_or_exit(std::expected<T, int>&& result)
{
    if (!result) {
        std::exit(result.error());
    }

    return std::move(result).value();
}

void unwrap_or_exit(std::expected<void, int>&& result)
{
    if (!result) {
        std::exit(result.error());
    }
}

} // namespace

TEST(Landlock, InitSucceeds)
{
    auto nnp = set_no_new_privs();
    ASSERT_TRUE(nnp) << "set_no_new_privs failed: " << nnp.error();

    auto lk = LandlockRuleSet::init();

    EXPECT_TRUE(lk) << "LandlockRuleSet::init failed: " << lk.error();
}

TEST(Landlock, AddReadableEtcRuleSucceeds)
{
    auto nnp = set_no_new_privs();
    ASSERT_TRUE(nnp) << "set_no_new_privs failed: " << nnp.error();

    auto lk = LandlockRuleSet::init();
    ASSERT_TRUE(lk) << "LandlockRuleSet::init failed: " << lk.error();

    auto res = lk->add_rule("/etc", LandlockAccess::Read);

    EXPECT_TRUE(res) << "add_rule failed: " << res.error();
}

TEST(Landlock, AddRuleForMissingPathFails)
{
    auto nnp = set_no_new_privs();
    ASSERT_TRUE(nnp) << "set_no_new_privs failed: " << nnp.error();

    auto lk = LandlockRuleSet::init();
    ASSERT_TRUE(lk) << "LandlockRuleSet::init failed: " << lk.error();

    auto res = lk->add_rule("/definitely/not/a/real/path", LandlockAccess::Read);

    EXPECT_FALSE(res);
}

TEST(LandlockBehavior, AllowsReadInsideAllowedDirectory)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto allowed_file = root / "allowed" / "a.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::Read));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                allowed_file.c_str(),
                O_RDONLY | O_CLOEXEC,
                0
            );

            if (fd < 0) {
                std::exit(-fd);
            }

            detail::sys_close(fd);
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, AllowsReadInsideSubdirectory)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto nested_file = root / "allowed" / "sub" / "nested.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::Read));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                nested_file.c_str(),
                O_RDONLY | O_CLOEXEC,
                0
            );

            if (fd < 0) {
                std::exit(-fd);
            }

            detail::sys_close(fd);
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, DeniesReadOutsideAllowedDirectory)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto secret_file = root / "secret" / "secret.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::Read));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                secret_file.c_str(),
                O_RDONLY | O_CLOEXEC,
                0
            );

            if (fd >= 0) {
                detail::sys_close(fd);
                std::exit(1);
            }

            std::exit(-fd);
        },
        ::testing::ExitedWithCode(EACCES),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, AllowsWriteWhenReadWriteIsGranted)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto allowed_file = root / "allowed" / "a.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::ReadWrite));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                allowed_file.c_str(),
                O_WRONLY | O_CLOEXEC,
                0
            );

            if (fd < 0) {
                std::exit(-fd);
            }

            detail::sys_close(fd);
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, DeniesWriteWhenOnlyReadIsGranted)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto allowed_file = root / "allowed" / "a.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::Read));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                allowed_file.c_str(),
                O_WRONLY | O_CLOEXEC,
                0
            );

            if (fd >= 0) {
                detail::sys_close(fd);
                std::exit(1);
            }

            std::exit(-fd);
        },
        ::testing::ExitedWithCode(EACCES),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, AllowsCreateFileWhenReadWriteIsGranted)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto new_file = root / "allowed" / "created.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::ReadWrite));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                new_file.c_str(),
                O_CREAT | O_WRONLY | O_CLOEXEC,
                0666
            );

            if (fd < 0) {
                std::exit(-fd);
            }

            detail::sys_close(fd);
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        ""
    );

    std::filesystem::remove_all(root);
}

TEST(LandlockBehavior, DeniesCreateFileWhenOnlyReadIsGranted)
{
    auto root = make_test_root();
    setup_landlock_tree(root);

    auto allowed_dir = root / "allowed";
    auto new_file = root / "allowed" / "created.txt";

    ASSERT_EXIT(
        {
            unwrap_or_exit(set_no_new_privs());

            auto lk = unwrap_or_exit(LandlockRuleSet::init());
            unwrap_or_exit(lk.add_rule(allowed_dir.c_str(), LandlockAccess::Read));
            unwrap_or_exit(lk.apply());

            int fd = detail::sys_open(
                new_file.c_str(),
                O_CREAT | O_WRONLY | O_CLOEXEC,
                0666
            );

            if (fd >= 0) {
                detail::sys_close(fd);
                std::exit(1);
            }

            std::exit(-fd);
        },
        ::testing::ExitedWithCode(EACCES),
        ""
    );

    std::filesystem::remove_all(root);
}

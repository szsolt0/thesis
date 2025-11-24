#pragma once
#include <mylib/detail/util.h>
#include <mylib/detail/common_syscall.h>

#include <expected>
#include <string_view>
#include <span>

#include <linux/seccomp.h>
#include <linux/filter.h>

#pragma push_macro("TRY_EXPECTED")
#include <mylib/detail/expected_macro.h>

namespace mylib {

namespace detail {

// list of filters by category
extern const std::span<std::pair<std::string_view, sock_fprog>> filter_categories;

} // namespace detail
std::expected<void, int> seccomp_better_strict() noexcept;

class SeccompBuilder;

class SeccompRuleView
{
	friend class SeccompBuilder;
	friend class SeccompRule;

	sock_fprog m_filter;

	__attribute__((always_inline))
	constexpr SeccompRuleView(sock_fprog const& filter) noexcept : m_filter{filter} {}

	public:

	std::expected<void, int> apply() noexcept
	{
		auto const res = detail::sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &m_filter);

		if (res != 0) {
			return std::unexpected {-res};
		}

		return {};
	}
};

class SeccompRule
{
	SeccompRuleView m_view;

	__attribute__((always_inline))
	void set_moved_from() noexcept
	{
		m_view.m_filter.filter = nullptr;
		m_view.m_filter.len = 0;
	}

	__attribute__((always_inline))
	void destroy() noexcept
	{
		if (!m_view.m_filter.filter) {
			// don't destroy memory if it's alreasy destroyed
			return;
		}

		detail::sys_munmap(
			m_view.m_filter.filter,
			m_view.m_filter.len * sizeof(*m_view.m_filter.filter)
		);
	}

	public:

	SeccompRule(SeccompRule const&) = delete;
	SeccompRule& operator=(SeccompRule const&) = delete;

	SeccompRule(SeccompRule&& other) noexcept : m_view{other.m_view}
	{
		other.set_moved_from();
	}

	SeccompRule& operator=(SeccompRule&& other) noexcept
	{
		if (this == &other) {
			return *this;
		}

		destroy();
		m_view = other.m_view;
		other.set_moved_from();

		return *this;
	}

	~SeccompRule() noexcept
	{
		destroy();
	}
};

class SeccompBuilder
{
	detail::OwnedFd m_fd;

	__attribute__((always_inline))
	SeccompBuilder(int const fd) noexcept : m_fd{fd} {}

	public:

	static std::expected<SeccompBuilder, int> init() noexcept;

	std::expected<void, int> allow(std::string_view what) noexcept;

	std::expected<SeccompRule, int> build() noexcept;

	std::expected<SeccompRuleView, int> build_static() noexcept;
};

/*std::expected<SeccompRule, int> seccomp_create_rules_v(std::span<std::string_view> const rules) noexcept
{
	auto builder = TRY_EXPECTED(SeccompBuilder::init());

	for (auto const& rule : rules) {
		TRY_EXPECTED(builder.allow(rule));
	}

	return builder.build();
}*/

} // namespace mylib

#pragma pop_macro("TRY_EXPECTED")

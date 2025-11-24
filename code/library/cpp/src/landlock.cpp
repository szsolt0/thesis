#include <mylib/landlock.h>

#include <array>
#include <span>
#include <utility>

namespace mylib {

static constexpr std::pair<char const*, LandlockAccess> landlock_default_paths_arr[] = {
	std::pair<char const*, LandlockAccess> {"/dev/null",    LandlockAccess::ReadWrite},
	std::pair<char const*, LandlockAccess> {"/dev/random",  LandlockAccess::Read},
	std::pair<char const*, LandlockAccess> {"/dev/urandom", LandlockAccess::Read},
	std::pair<char const*, LandlockAccess> {"/proc/self",   LandlockAccess::ReadWrite},
	std::pair<char const*, LandlockAccess> {"/proc",        LandlockAccess::Read},
	std::pair<char const*, LandlockAccess> {"/bin",         LandlockAccess::ReadExecute},
};

constexpr std::span<const std::pair<char const*, LandlockAccess>>
detail::landlock_default_paths {landlock_default_paths_arr, std::size(landlock_default_paths_arr)};

} // namespace mylib

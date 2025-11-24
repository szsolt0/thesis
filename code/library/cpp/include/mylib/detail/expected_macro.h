// expected_macro.h
// Helps to work with std::expected. Can be included multiple times.
// Recommended to use with pragma push/pop macro.
// Author: Zsolt Sebe

#define TRY_EXPECTED(expr) ({\
	auto _tmp = (expr); \
	if (!_tmp) return std::unexpected {_tmp.error()}; \
	*_tmp; \
})

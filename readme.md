# xscan
Simple header-only IDA-style code scanner
```cpp
#include <xscan.hpp>

using function_t = std::add_pointer_t<void(std::int32_t arg)>;

function_t function = xscan::pattern("E8 ? ? ? ?")
	.scan(xscan::pe_sections(image_base))
	.add(1).rip();
```
```cmake
FetchContent_Declare(xscan
	GIT_REPOSITORY
		"https://github.com/eliasmoflag/xscan.git"
	GIT_TAG
		<tag>
)
FetchContent_MakeAvailable(xscan)
```

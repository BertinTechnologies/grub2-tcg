#pragma once

#define ERROR(str, ...) printf("ERROR [%s:%u] " str "\n", __FUNCTION__, __LINE__, __VA_ARGS__)

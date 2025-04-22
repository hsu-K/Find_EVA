#pragma once
#pragma once
#include <windows.h>

#include "Recording.hpp"

#define MAX_MUT_STR 260

enum MutationType {
	MUT_FAIL,		// call fails -- integer error code
	MUT_SUCCEED,	// call returns success
	MUT_ALT_STR,	// alternative result -- string value
	MUT_ALT_NUM,	// alternative result -- integer value
	MUT_ALT_TUP,	// alternative result -- tuple value
	MUT_HIDE,		// hide a value from a larger structure(context ? )
	MUT_RND_NUM,	// random result -- integer value (always random for repeated calls)
	MUT_RND_TUP		// random result -- tuple value (always random for repeated calls)
};

union MutationValue {
	wchar_t szValue[MAX_MUT_STR];
	int tupValue[2];
	DWORD nValue;
};

class Mutation {
public:
	Mutation() : mutType(MUT_FAIL), mutValue(), rec(), next(nullptr) {}
	// mutation
	MutationType mutType;
	MutationValue mutValue;

	// recording
	Recording rec;

	Mutation* next;
};

// calls without context can only hold 1 mutation per execution
struct MutationNoCtx {
	MutationType mutType;
	MutationValue mutValue;
};


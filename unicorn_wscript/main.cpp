#include "../unicorn/include/unicorn/unicorn.h"

#include <xstring>
using namespace std;
#include "PeEmu.h"

int main(int argv, char** argc)
{
	// Check file & other
	wstring wSampleName;
	wchar_t bufname[MAX_PATH] = { 0, };
	printf("please samlple path: ");
	scanf("%ws", bufname);
	wSampleName = bufname;
	if (0 >= wSampleName.length())
		return 0;

	// x86 or x64
	// bool x8664flag = false;

	// Init PeEmu
	PeEmu pe(wSampleName);
	if (!pe.puGetInitstatus())
		return 0;
	pe.puInitEmu();

	// Run PeEmu
	pe.puRun();

	return 0;
}
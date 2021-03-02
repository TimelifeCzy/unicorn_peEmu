#pragma once
/*
	负责Win_dll字段解析
	函数名称-参数-参数个数
*/

class WinDLLJson
{
public:
	WinDLLJson();
	~WinDLLJson();

public:
	bool puInitDLLJson() { return this->prInitDLLJson(); }
	bool puGetApiParamNumter() { return this->prGetApiParamNumter(); }

private:

	bool prInitDLLJson();
	bool prGetApiParamNumter();

};
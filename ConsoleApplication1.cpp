#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>
#include <mutex>
#include <chrono>
#include <regex>
#include <sstream>
#include <ctime>
using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define IP_LEN 16 //宏定义 ip地址 数组长度
#define MAC_LEN 18 //宏定义 mac地址 数组长度
HANDLE consolehwnd;//创建控制台句柄 实现输出绿色字体
int result_count_ip = 0;//存活ip结果总数
int result_count_port = 0;//开发端口结果总数
std::mutex consoleMutex;  // 定义一个多线程互斥锁
void Survival_ipScan_fun(vector<string>& ipresult_tmp);//C段存活扫描start函数声明 参数：c段ip
int send_arp_request_threadFunction(int threadID, std::string target_ip);// 发送ARP请求 线程函数 声明
bool send_arp_request_Function(std::string dst_ip);// 发送ARP请求获取存活ip
vector<string> split(const string str, char delim);//根据字符 分割字符串返回一个vector容器
void ip_PortScan_fun(string dst_ip);//ip端口扫描start函数声明 参数：ip
int connect_socket_server_port_threadFunction(string dst_ip, int port);//端口扫描线程函数(阻塞模式) 声明
string GetSystemTime();//获取系统时间

//入口 参数：控制台传入参数个数，指针数组
int main(int argc, char* args[]) {
	printf("\n");
	printf("***********************************************************************************\n");
	printf("【+】局域网C段探测\n");
	printf("【+】C段存活ip扫描(01)\n");
	printf("【+】目标ip端口扫描(02)\n");
	printf("【+】https://github.com/0x6C696A756E/Scan-for-ip-addresses-and-ports-in-segment-C\n");
	printf("【+】https://blog.csdn.net/qq_29826869\n");
	printf("【+】- 0x6C696A756E -\n");
	printf("【+】Date 2023/11/17\n");
	printf("【+】用法：\n");
	printf("【+】%s 192.168.1.1/24 C段ip存活扫描\n", args[0]);
	printf("【+】%s 192.168.1.188 目标ip端口扫描\n", args[0]);
	printf("***********************************************************************************\n");
	printf("\n");
	consolehwnd = GetStdHandle(STD_OUTPUT_HANDLE);//实例化控制台句柄
	if (argc > 1) {
		//取指针数组 args[01] 控制台参数字符串后三位
		char temp_a, temp_b, temp_c;
		temp_a = args[1][strlen(args[1]) - 3];
		temp_b = args[1][strlen(args[1]) - 2];
		temp_c = args[1][strlen(args[1]) - 1];
		struct in_addr s;//ip地址结构体
		if (inet_pton(AF_INET, split(args[1], '/')[0].c_str(), &s)&&temp_a==0x2F&&temp_b==0x32&&temp_c==0x34) {
			SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色字体
			printf("[+] 匹配到C段IP扫描模式\n");
			cout << "目标C段：" << args[1] << endl;
			SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
			vector<string> ipresult_tmp = split(args[1], '.');//分割ip 传入Survival_ipScan_fun函数 再重组
			Survival_ipScan_fun(ipresult_tmp);//调用扫描C段起始函数
			return 0;
		}
		//判断输入ip是否是合法的IPv4
		if (inet_pton(AF_INET, args[1], &s)) {
			SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色字体
			printf("[+] 匹配到端口扫描模式\n");
			cout << "目标ip：" << args[1] << endl;
			SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
			//首次判断用户输入ip 是否存活以及路由是否可达
			if (send_arp_request_Function(args[1])) {
				ip_PortScan_fun(args[1]);//调用扫描端口起始方法
				//printf("ip存活，路由可达\n");
				return 0;
			}
			printf("[-] Error! ip不存活或路由不可达。\n");
			return 0;
		}
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_RED);//设置红色字体
		printf("[-] 参数错误!\n");
		printf("[+] 仅支持局域网探测\n");
		printf("[+] %s 192.168.1.1/24 C段ip存活扫描\n",args[0]);
		printf("[+] %s 192.168.1.188 目标ip端口扫描\n", args[0]);
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	return 0;
}

// 发送ARP请求探测用户输入ip是否存活
bool send_arp_request_Function(std::string dst_ip) {
	struct in_addr addr;
	// 将点分十进制的IPv4地址转换为网络字节序的32位整数
	if (inet_pton(AF_INET, dst_ip.c_str(), &addr) <= 0) {
		std::cerr << "Invalid IP address." << std::endl;
	}
	ULONG mac_addr[2];
	ULONG mac_addr_len = 6;
	DWORD ret = SendARP(addr.s_addr, 0, mac_addr, &mac_addr_len);
	if (ret == NO_ERROR) {
		return true;
	}
	return false;
}
// 发送ARP请求获取存活ip 线程函数实现
int send_arp_request_threadFunction(int threadID, std::string dst_ip) {
	struct in_addr addr;
	// 将点分十进制的IPv4地址转换为网络字节序的32位整数
	if (inet_pton(AF_INET, dst_ip.c_str(), &addr) <= 0) {
		std::cerr << "Invalid IP address." << std::endl;
	}
	//unsigned long ipaddr = inet_addr(dst_ip.c_str());
	ULONG mac_addr[2];
	ULONG mac_addr_len = 6;
	DWORD ret = SendARP(addr.s_addr, 0, mac_addr, &mac_addr_len);
	char mac_str[MAC_LEN];
	if (ret == NO_ERROR) {
		sprintf_s(mac_str, MAC_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", ((unsigned char*)&mac_addr)[0], ((unsigned char*)&mac_addr)[1], ((unsigned char*)&mac_addr)[2], ((unsigned char*)&mac_addr)[3], ((unsigned char*)&mac_addr)[4], ((unsigned char*)&mac_addr)[5]);
		// 使用互斥锁锁定对控制台的访问 避免资源抢占
		std::unique_lock<std::mutex> lock(consoleMutex);
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色
		if (mac_str[0]==0x30&& mac_str[1] == 0x30&& mac_str[2] == 0x3a&& mac_str[3] == 0x30&& mac_str[4] == 0x43) {
			cout << "[" << GetSystemTime() << "]Thread:" << "0x" << std::hex << std::this_thread::get_id() << std::dec << "  " << dst_ip << "  MAC：" << mac_str <<" (VMware虚拟机)" << endl;
		}
		else
		{
			cout << "[" << GetSystemTime() << "]Thread:" << "0x" << std::hex << std::this_thread::get_id() << std::dec << "  " << dst_ip << "  MAC：" << mac_str << endl;
		}
		result_count_ip += 1;//ip总数+1
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	return 0;
}


//C段扫描起始函数
void Survival_ipScan_fun(vector<string>& ipresult_tmp) {
	const int numThreads = 256;//255个线程 循环从0开始 <256
	std::thread threads[numThreads];//实例化255个线程对象数组
	// 获取程序开始时间点
	auto start = std::chrono::high_resolution_clock::now();
	vector<string> ipresult;//存放生成的c段ip 容器
	//根据用户输入ip 生成C段ip
	for (int i = 0; i < numThreads; i++)
	{
		string ip = ipresult_tmp[0] + '.' + ipresult_tmp[1] + '.' + ipresult_tmp[2] + '.' + std::to_string(i);
		ipresult.push_back(ip);
	}
	for (int i = 0; i < numThreads; i++) {
		//创建线程并启动
		threads[i] = std::thread(send_arp_request_threadFunction, i, ipresult[i]);
	}
	// 等待所有线程完成
	for (int i = 0; i < numThreads; i++) {
		threads[i].join();
	}
	// 获取程序执行完成的时间点
	auto end = std::chrono::high_resolution_clock::now();
	// 计算耗时时间（秒）
	auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
	//判断ip结果总数取反值为0 false
	if (!result_count_ip) {
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_RED);//设置红色字体
		printf("[-] 没有探测到存活ip,或路由不可达！\n");
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	printf("\n");
	SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色字体
	std::cout << "[+] 程序执行耗时: " << duration.count() << "秒，共有:" << result_count_ip << "个ip存活。" << std::endl;
	SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
}

//根据字符 分割字符串返回一个vector容器
vector<string> split(const string str, char delim) {
	stringstream stream(str);
	vector<string> result;
	string token;
	while (getline(stream, token, delim)) {
		result.push_back(token);
	}
	return result;
}

//端口扫描线程函数实现
int connect_socket_server_port_threadFunction(string dst_ip, int port) {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cout << "Failed to initialize Winsock." << std::endl;
		return 0;
	}
	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == INVALID_SOCKET) {
		std::cout << "Failed to create socket." << std::endl;
		WSACleanup();
		return 0;
	}
	sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	serverAddress.sin_addr.s_addr = inet_addr(dst_ip.c_str());
	// 连接到服务器
	if (connect(clientSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) != 0) {
		closesocket(clientSocket);
		WSACleanup();
		return 0;
	}
	// 使用互斥锁锁定对控制台的访问 避免资源抢占
	std::unique_lock<std::mutex> lock(consoleMutex);
	SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色字体
	//printf("[+] Connected Port %d is Successfully!\n", port);
	cout << "["<< GetSystemTime() <<"] Thread:" << "0x" << std::hex << std::this_thread::get_id() << std::dec << "  " <<"Port " << port << " is Successfully!" << std::endl;;
	result_count_port++;
	SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	closesocket(clientSocket);
	WSACleanup();
	return 0;
}

//ip端口扫描起始函数实现
void ip_PortScan_fun(string dst_ip) {
	const int totalNumbers = 65535; //总数
	const int numbersPerBatch = 5000;//每份数量(可以理解为线程并发数)
	int currentNumber = 1;//起始从1开始
	std::vector<std::vector<int>> ip_batches;//父容器
	while (currentNumber <= totalNumbers) {
		std::vector<int> batch;//临时子容器
		//每份循环5000次，最后一份少于5000次 所有要加 并且条件 && currentNumber<= totalNumbers
		for (int i = 0; i < numbersPerBatch && currentNumber <= totalNumbers; i++) {
			batch.push_back(currentNumber);
			currentNumber++;//起始值 ++
		}
		ip_batches.push_back(batch);//把每份子容器添加进父容器
	}
	std::vector<std::thread> threads;//线程容器
	// 获取程序开始时间点 总时间
	auto start = std::chrono::high_resolution_clock::now();
	int count = 1;//总轮数
	//遍历所有的端口子容器
	for (const auto& batch : ip_batches) {
		// 获取线程开始时间点
		auto start = std::chrono::high_resolution_clock::now();
		//开启多少个线程 按子容器的数据量
		for (int i = 0; i < batch.size(); i++) {
			//创建线程并启动
			threads.push_back(std::thread(connect_socket_server_port_threadFunction, dst_ip, batch[i]));//阻塞
		}
		// 等待所有线程完成
		for (int i = 0; i < threads.size(); i++) {
			threads[i].join();
		}
		// 获取线程执行完成的时间点
		auto end = std::chrono::high_resolution_clock::now();
		// 计算耗时时间（秒）
		auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
		cout << "第：" << count << "轮已完成 ["<< batch[0]<<"-"<< batch[batch.size()-1]<< "] 线程数：" << batch.size() << " 线程执行耗时: " << duration.count() << "秒" << endl;
		threads.clear();
		count++;
	}
	// 获取程序执行完成的时间点 总时间
	auto end = std::chrono::high_resolution_clock::now();
	// 计算耗时时间（秒）
	auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
	//判断port结果总数取反值为0 false
	if (!result_count_port) {
		printf("\n");
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_RED);//设置绿色字体
		printf("[-] 未开放任何端口！\n");
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	SetConsoleTextAttribute(consolehwnd, FOREGROUND_INTENSITY | FOREGROUND_GREEN);//设置绿色字体
	std::cout << "[+] 程序执行耗时: " << duration.count() << "秒，共有:" << result_count_port << "个端口开放。" << std::endl;
	SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
}

//获取系统时间
string GetSystemTime() {
	time_t now = time(0);
	char timestamp[80];
	struct tm tstruct;
	tstruct = *localtime(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tstruct);
	string time = timestamp;
	return time;
}
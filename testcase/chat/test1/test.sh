#!/bin/bash

# 编译客户端和服务器程序
gcc -o test_client client.c -pthread
gcc -o test_server server.c -pthread

# 创建测试目录
mkdir -p ./client1
mkdir -p ./client2

# 复制编译好的程序到测试目录
cp test_client ./client1/
cp test_client ./client2/

# 创建测试输入文件
echo "6001" > ./client1/input.txt
echo "REGISTER user1 Y Y" >> ./client1/input.txt
echo "WHO" >> ./client1/input.txt
echo "@ALL:Hello everyone!" >> ./client1/input.txt
echo "EXIT" >> ./client1/input.txt

echo "6002" > ./client2/input.txt
echo "REGISTER user2 Y Y" >> ./client2/input.txt
echo "WHO" >> ./client2/input.txt
echo "@user1:Hi user1!" >> ./client2/input.txt
echo "EXIT" >> ./client2/input.txt

# 启动服务器
./test_server > server.log 2>&1 &
SERVER_PID=$!

# 等待服务器启动
sleep 2

# 启动第一个客户端
cd ./client1/
./test_client < input.txt > client1.log 2>&1 &
CLIENT1_PID=$!
cd ..

# 等待第一个客户端启动
sleep 2

# 启动第二个客户端
cd ./client2/
./test_client < input.txt > client2.log 2>&1 &
CLIENT2_PID=$!
cd ..

# 等待测试完成
sleep 10

# 检查日志文件
echo "=== Server Log ==="
cat server.log
echo "=== Client1 Log ==="
cat ./client1/client1.log
echo "=== Client2 Log ==="
cat ./client2/client2.log

# 清理进程
pkill test_client
pkill test_server

# 清理文件
rm -rf ./client1
rm -rf ./client2
rm test_server
rm test_client
rm server.log

echo "Test completed. Check the logs above for results." 
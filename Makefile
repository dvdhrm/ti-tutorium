all:
	gcc -o bthost src/*.c -Wall -Isrc -lpthread -D_GNU_SOURCE -lbluetooth -DBUILD_ENABLE_DEBUG

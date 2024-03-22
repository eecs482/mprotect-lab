main.exe: main.cpp
	g++ --std=c++17 $^ -o $@
clean:
	-rm main.exe
.PHONY: clean

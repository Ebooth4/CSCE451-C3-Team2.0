file1 = c3ex1
file2 = c3ex2
default: all

all: compile run

compile:
	g++ $(file1).cpp -o $(file1)
	g++ $(file2).cpp -o $(file2)

run:
	./$(file1)
	./$(file2)

clean:
	rm $(file1).exe
	rm $(file2).exe
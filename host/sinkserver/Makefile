CXX     :=g++
TARGET  :=sinkserver
SOURCES :=sinkserver.cpp

all: $(TARGET) $(FILTERSS)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -pthread $(SOURCES) $^ -o $@

clean:
	rm -f $(TARGET) $(OBJECTS) *.core *~

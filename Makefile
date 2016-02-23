default: build

clean:
	rm bin/docker-machine-*

build:
	GOGC=off go build -o bin/docker-machine-driver-cloudstack bin/main.go

install: build
	cp ./bin/docker-machine-driver-cloudstack /usr/local/bin/

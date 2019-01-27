default:
	go fmt forest/forest.go
	go fmt forest.go
	go run forest.go

test:
	go fmt test.go
	go build test.go
	AWS_SDK_LOAD_CONFIG=true AWS_DEFAULT_PROFILE=farrellit ./test


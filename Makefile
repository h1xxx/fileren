build:
	CGO_ENABLED=0 go build -o bin/sectest cmd/sectest.go
	CGO_ENABLED=0 go build -o bin/xxetest cmd/xxetest.go

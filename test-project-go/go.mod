module test-vulnerable-go

go 1.19

require (
	github.com/gin-gonic/gin v1.6.0 // Known vulnerabilities
	github.com/gorilla/websocket v1.4.0 // Known vulnerabilities
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 // Old version with vulnerabilities
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 // Old version with vulnerabilities
	gopkg.in/yaml.v2 v2.2.2 // Known vulnerabilities
)

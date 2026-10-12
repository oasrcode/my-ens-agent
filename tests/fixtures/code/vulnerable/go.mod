module example.com/vulnerable

go 1.21

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/satori/go.uuid v1.2.0
)

replace example.com/local => ../local

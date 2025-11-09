package main

import (
	"fmt"
	"os"
	"time"

	"go get github.com/golang-jwt/jwt/v5"
	"go get github.com/joho/godotenv"
)

func main(){
	jws,err:=createJwt("ibrahim")
	 if err != nil {
        fmt.Println("Error creating token:", err)
        return
    }
	fmt.Println(jws)
	fmt.Println(verifyToken(jws))
	
}

type MyClaim struct{
	Username string  `json:"username"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func createJwt(username string) (string,error){
	godotenv.Load()

	secretkey:=os.Getenv("JWT_SECRET")
	claims:=MyClaim{
         Username: username,
		 Role: "admin",
		 RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour*24)),
		 },
	}

   token:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
fmt.Println(token)
   tokenstr,err:=token.SignedString([]byte(secretkey))
   return  tokenstr,err
}

func verifyToken(secretjwt string) bool {
	godotenv.Load()

	secretkey:=[]byte(os.Getenv("JWT_SECRET"))

	token,err:=jwt.ParseWithClaims(secretjwt,&MyClaim{},func(t *jwt.Token) (any, error) {
		if _,ok:=t.Method.(*jwt.SigningMethodHMAC);!ok{
			return  nil,fmt.Errorf("unexpected signing method")
		}
		return secretkey,nil
	})
		if err != nil {
		fmt.Println("Invalid token:", err)
		return false
	}

	if claims,ok:=token.Claims.(*MyClaim);ok && token.Valid{
		fmt.Println("Username:", claims.Username)
		fmt.Println("Expires:",claims.ExpiresAt.Time)
	}else {
		fmt.Println("Invalid claims")
		return  false
	}
	return true
}
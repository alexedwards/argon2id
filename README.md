# Lambda Argon
Utilize the Argon2ID cryptographically secure hashing algorithm with parameters tuned specifically to run optimally on AWS Lambda.

Originally forked from github.com/alexedwards/argon2id but modified significantly to work optimally with AWS Lambda, cleanup test cases, and add new test cases.

# Original README
This package provides a convenience wrapper around Go's [argon2](https://pkg.go.dev/golang.org/x/crypto/argon2?tab=doc) implementation, making it simpler to securely hash and verify passwords using Argon2.
It enforces use of the Argon2id algorithm variant and cryptographically-secure random salts.

## How to Build locally
1. `make build`

## How to Test locally
1. `make test`

## How to Use
1. `go get github.com/seantcanavan/lambda_argon@latest`
2. `import github.com/seantcanavan/lambda_argon`
3. Steps for adding or updating a password for a user:
   1. Get the user password input from your lambda req: `req.Body.password` or `req.QueryStringParameters["password"]` or similar
   2. Hash the password to store in your database: `hash, err := lambda_argon.Hash(password)`
   3. Store the hash in your database: `user.UpdatePassword(ctx, hash)`
4. Steps for validating passwords / logging in for a user:
   1. Get the user password input from your lambda req: `req.Body.password` or `req.QueryStringParameters["password"]` or similar
   2. Get the hash for the user in your database: `hash, err := user.GetHash(ctx, userID)`
   3. Try to match the user input against the hash: `match, err := lambda_argon.Match(password, hash)`

## Sample Login Lambda Handler Example
``` go
func LoginLambda(ctx context.Context, lambdaReq events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var loginReq LoginReq
	err := json.Unmarshal(lambdaReq.Body, &loginReq)
	if err != nil {
		return ERROR - internal server
	}

	adminByEmail, err := admin.GetByEmail(ctx, loginReq.Email)
	if err != nil {
		return ERROR - not found
	}

	// check if the password provided matches the hashed one saved in this admin
	match, err := lambda_argon.Match(loginReq.Password, adminByEmail.Password)
	if err != nil {
		return ERROR - bad request
	}

	// check if the password matches
	if !match {
		return ERROR - unauthorized
	}

	return SUCCESS
}
```

## Sample Update Password Lambda Handler Example
``` go
func UpdatePasswordLambda(ctx context.Context, lambdaReq events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var updatePasswordReq UpdatePasswordReq
	err := json.Unmarshal(lambdaReq.Body, &updatePasswordReq)
	if err != nil {
		return ERROR - internal server
	}

    adminByEmail, err := admin.GetByEmail(ctx, loginReq.Email)
	if err != nil {
		return ERROR - not found
	}

	match, err := lambda_argon.Match(updatePasswordReq.Password, adminByEmail.Password)
	if err != nil {
		return ERROR - bad request
	}

	// check if the password matches
	if !match {
		return ERROR - unauthorized
	}

	hash, err := argon2id.Hash(updatePasswordReq.NewPassword)
	if err != nil {
		return ERROR - bad request
	}

	httpStatus, err = admin.SetPassword(ctx, adminById.ID, hash)
	if err != nil {
		return ERROR - conflict
	}

    return SUCCESS
}
```

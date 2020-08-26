# PHPValidator
Help validate GET and POST requests and handle JWT Authentication
This was created with the intent to make validating requests in PHP and to handle JWT Authentication.

## Overview
At the begining of each endpoint file, you include the validator.php script and then define the functions your endpoint handles inside a call to `validate`.
Here's an example of a validate call:

```
validate(array(
    "POST"=>array(
      new Func('login', array(
        new Argument('email', 'string', Validator::EMAIL()),
        new Argument('password', 'string', Validator::MAXLENGTH(32))
      ), false
    ),
    "GET"=>array(
      new Func('userInfo', array(
        new Argument('user_id', 'string', Validator::UUID(), true)
      )
    )
  )
);

function login($email, $password, $conn){
  ...
}

function userInfo($user_id, $conn){
  ...
}
```
In the above code, we define 2 functions: `login` and `userInfo`. 
`login` is called with 2 arguments from a POST request. The argument `email` is validated against an email validator and the argument `password` is validated against a max length validator. Note the `false` after the arguments definitions means that it is not a validated call, so it doesn't require a Json Web Token (JWT) in the Authentication header.

`userInfo` is called with 1 argument from a GET request. The `user_id` argument is validated against a UUID validator. Note the true in the argument definition means that it's a validated argument, meaning it expects to find `user_id` in the JWT's payload. Also, by default, this function is validated and expects to receive a JWT in the request.

After these definitions are given to the `validate` function, we declare their functions in the code itself with the same named arguments we provided to validate. Validate will automatically parse the arguments to the proper types and validate them against the validators. If there is a problem, an error code is sent and execute stops. Otherwise, it proceeds and then calls our functions. Note, it will inject a PDO database connection `$conn` into the end of our functions.


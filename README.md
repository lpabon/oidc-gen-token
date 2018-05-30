# oidc-gen-token
This simple program is used to generate an OpenID JWT Token from the command
line and if requested, saved to a file.

This is program is heavily based on the examples from [go-oidc](https://github.com/coreos/go-oidc).

# Installation

```
go install github.com/lpabon/oidc-gen-token
```

# Usage

Here is a sample usage:

```
$ oidc-gen-token --client-id=<...> \
    --client-secret=<...> \
	--issuer=https://accounts.google.com \
	--save-token
```

# Provider
You will also need to setup an OpenID Connect provider. Here are a few examples:

## Google
Follow the examples from [go-oidc/examples](https://github.com/coreos/go-oidc/tree/v2/example#examples)

## Auth0.com
* Create an application
    * Note down the client id and secret
	* Setup the callback URL to `http://127.0.0.1:5556/auth/callback`.
    * You will also need to click on _Advanced Settings_ at the bottom of the
	  application setup page and then click on _OAuth_. Lastly, enable
	  _OIDC Conformant_.
    * Save the application
* Click on Users, and create a sample user.


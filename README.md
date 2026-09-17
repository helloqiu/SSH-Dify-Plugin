# SSH Command Execution Plugin

**Author:** [Steven Lynn](https://github.com/stvlynn)
**Version:** 0.0.3
**Type:** tool

## Description

The SSH Command Execution Plugin allows users to execute commands on remote servers via SSH protocol. It supports both password and private key authentication methods.
![](./_assets/image.png)

> Don't know where to start? Try this [DSL Template](https://raw.githubusercontent.com/stvlynn/SSH-Dify-Plugin/refs/heads/main/example.yml) !

## Features

- Supports password and private key authentication
- Supports specifying the private key type (`auto`, `rsa`, `ed25519`, `ecdsa`, `dsa`), with auto-detection as the default
- Accepts multi-line scripts and `&&` / `;` command chains
- Executes remote commands and returns standard output and standard error
- Securely handles connection and authentication errors

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| host | string | Yes | Hostname or IP address of the remote server |
| port | number | Yes | SSH port, default is 22 |
| username | string | Yes | Username for authentication |
| auth_type | select | Yes | Authentication type: password or key |
| password | string | Conditional | Password for password authentication (required if auth_type is password) |
| private_key | string | Conditional | Private key content for key authentication (required if auth_type is key) |
| passphrase | string | No | Passphrase for the private key (if the key is encrypted) |
| key_type | select | No | Private key type: `auto` (default), `rsa`, `ed25519`, `ecdsa` or `dsa`. Only used when auth_type is key |
| command | string | Yes | Command to execute on the remote server |

### About Private Key Type

When `auth_type` is `key`, `key_type` controls how the private key is parsed:

- `auto` (default): tries Ed25519, ECDSA, RSA and DSA in turn. Works in most cases, but a mismatched key type produces a generic error.
- `rsa` / `ed25519` / `ecdsa` / `dsa`: parses the key with the exact type you choose and returns a specific error when the key does not match, which makes troubleshooting a bad or mismatched key much easier.

`dsa` keys are only supported by paramiko releases that still ship DSS/DSA support.

### Multi-line Commands

`command` accepts a whole script, not just a single line. Real newlines, `&&` / `;` chains, pipelines, `for` / `if` blocks and heredocs are all handed to the remote shell as one script, and it runs in the login shell (so `cd` on one line affects the following lines). `exit_status` is the exit status of the whole script.

```python
"command": "cd /srv/app && git pull"          # chain
"command": "echo '1' && echo '2'"             # chain
"command": "echo '1'\necho '2'"               # real newline
```

Note that the command must contain **real newlines**. A literal `\n` (backslash + n) is passed to the shell as-is and is not converted into a line break — that is intentional, since `printf 'a\nb'` and `sed 's/a\nb/'` rely on the literal sequence.

## Safety Tip

Keep your instance IP and password safe in **Environment Varriable -> secret**!

![](./_assets/environment.png)

## Input and Output Example

### Input:
```json
{
  "private_key": "",
  "passphrase": "",
  "key_type": "auto",
  "host": "192.************1",
  "port": "22",
  "username": "root",
  "auth_type": "password",
  "password": "T************87",
  "command": "neofetch"
}
```

### Output:
```json
{
  "text": "",
  "files": [],
  "json": [
    {
      "stderr": "",
      "stdout": "***some output***",
      "success": true
    }
  ]
}
```

## Security Considerations

- Ensure you have permission to access the target server
- Sensitive information such as private keys and passwords should be kept secure
- Follow the principle of least privilege, granting only necessary execution permissions

## License

[MIT](./LICENSE)




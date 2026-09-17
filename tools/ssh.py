from collections.abc import Generator
from typing import Any, Dict, Optional
import paramiko
import io
import socket
import threading
import traceback

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

# 私钥类型 -> paramiko 中对应的解析类名（按尝试顺序排列）
KEY_TYPE_CLASS_NAMES: dict[str, tuple[str, ...]] = {
    "rsa": ("RSAKey",),
    "ed25519": ("Ed25519Key",),
    # paramiko 2.x 使用 DSSKey，3.x 中为 DSAKey（DSSKey 为其别名）
    "dsa": ("DSAKey", "DSSKey"),
    "ecdsa": ("ECDSAKey",),
}

# key_type 为 auto 时按此顺序自动尝试
AUTO_KEY_CLASS_NAMES: tuple[str, ...] = ("Ed25519Key", "ECDSAKey", "RSAKey", "DSAKey", "DSSKey")


def _load_private_key(private_key: str, passphrase: Optional[str], key_type: Optional[str]):
    """按指定类型（或自动探测）解析私钥内容，返回 paramiko PKey 对象。"""
    normalized = (key_type or "auto").strip().lower()

    if normalized == "auto":
        class_names = AUTO_KEY_CLASS_NAMES
    elif normalized in KEY_TYPE_CLASS_NAMES:
        class_names = KEY_TYPE_CLASS_NAMES[normalized]
    else:
        supported = ", ".join(["auto", *KEY_TYPE_CLASS_NAMES])
        raise paramiko.SSHException(
            f"Unsupported private key type: {key_type}. Supported values: {supported}."
        )

    key_classes: list[type] = []
    for key_cls_name in class_names:
        key_cls = getattr(paramiko, key_cls_name, None)
        if key_cls is not None and key_cls not in key_classes:
            key_classes.append(key_cls)

    if not key_classes:
        raise paramiko.SSHException(
            f"Installed paramiko does not support private key type: {normalized}"
        )

    password_arg = passphrase if passphrase else None
    key_file = io.StringIO(private_key)
    last_key_error: Exception | None = None

    for key_cls in key_classes:
        key_file.seek(0)
        try:
            return key_cls.from_private_key(key_file, password=password_arg)
        except paramiko.PasswordRequiredException as e:
            raise paramiko.SSHException("Passphrase is required for encrypted private key") from e
        except Exception as e:
            last_key_error = e
            continue

    if normalized == "auto":
        raise paramiko.SSHException(
            f"Unsupported or invalid private key: {str(last_key_error)}"
        ) from last_key_error
    raise paramiko.SSHException(
        f"Failed to parse private key as {normalized}: {str(last_key_error)}"
    ) from last_key_error


def _read_streams(stdout, stderr) -> tuple[bytes, bytes]:
    """并发读取 stdout 与 stderr。

    串行读取（先读完 stdout 再读 stderr）时，若对端把超过 channel window 的数据写进
    stderr，窗口写满后会阻塞对端，stdout 永远拿不到 EOF，导致命令卡死。
    """
    buffers: dict[str, bytes] = {}

    def reader(name: str, stream) -> None:
        buffers[name] = stream.read()

    threads = [
        threading.Thread(target=reader, args=("stdout", stdout)),
        threading.Thread(target=reader, args=("stderr", stderr)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    return buffers.get("stdout", b""), buffers.get("stderr", b"")


class SshTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        host = tool_parameters.get('host')
        port = int(tool_parameters.get('port', 22))
        username = tool_parameters.get('username')
        auth_type = tool_parameters.get('auth_type')
        password = tool_parameters.get('password')
        private_key = tool_parameters.get('private_key')
        passphrase = tool_parameters.get('passphrase')
        key_type = tool_parameters.get('key_type')
        command = tool_parameters.get('command')
        
        if not host or not username or not command:
            yield self.create_json_message({
                "error": "Missing required parameters: host, username, and command are required."
            })
            return
            
        if auth_type == 'password' and not password:
            yield self.create_json_message({
                "error": "Password is required for password authentication."
            })
            return
        elif auth_type == 'key' and not private_key:
            yield self.create_json_message({
                "error": "Private key is required for key authentication."
            })
            return
            
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if auth_type == 'password':
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=10
                )
            else:  # key authentication
                pkey = _load_private_key(private_key, passphrase, key_type)

                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    pkey=pkey,
                    timeout=10
                )
                
            env_cmd = (
                'if [ -n "$ZSH_VERSION" ] && [ -f "$HOME/.zshrc" ]; then . "$HOME/.zshrc"; '
                'elif [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; '
                'elif [ -f "$HOME/.profile" ]; then . "$HOME/.profile"; '
                'fi; '
                'export PATH="$PATH:/usr/local/bin"; '
                f'{command}'
            )

            stdin, stdout, stderr = client.exec_command(env_cmd)
            
            stdout_bytes, stderr_bytes = _read_streams(stdout, stderr)
            exit_status = stdout.channel.recv_exit_status()

            stdout_str = stdout_bytes.decode('utf-8', errors='replace')
            stderr_str = stderr_bytes.decode('utf-8', errors='replace')
            
            client.close()
            
            result = {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_status": exit_status,
                "success": exit_status == 0
            }
            
            yield self.create_json_message(result)
            
        except paramiko.AuthenticationException as e:
            yield self.create_json_message({
                "error": "Authentication failed. Please check your credentials.",
                "detail": str(e),
                "exception_type": e.__class__.__name__,
                "success": False
            })
        except paramiko.SSHException as e:
            yield self.create_json_message({
                "error": f"SSH error: {str(e)}",
                "detail": str(e),
                "exception_type": e.__class__.__name__,
                "success": False
            })
        except socket.error as e:
            yield self.create_json_message({
                "error": f"Connection error: {str(e)}",
                "detail": str(e),
                "exception_type": e.__class__.__name__,
                "success": False
            })
        except Exception as e:
            yield self.create_json_message({
                "error": f"Error: {str(e)}",
                "detail": str(e),
                "exception_type": e.__class__.__name__,
                "traceback": traceback.format_exc(),
                "success": False
            })

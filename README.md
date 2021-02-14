# 🐳 SSHD

Minimal Alpine Linux Docker image with `sshd` exposed and `rsync` installed.
It is a mirror of  this repository with my modification that doesn't use a variable `SSH_USERS` anymore instead requires json users from the /users.json file. 

## Environment Options

Configure the container with the following environment variables or optionally mount a custom sshd config at `/etc/ssh/sshd_config`:

### General Options

- `SSH_ENABLE_ROOT` if "true" unlock the root account
- `SSH_ENABLE_PASSWORD_AUTH` if "true" enable password authentication (disabled by default)
- `MOTD` change the login message

### SSH Options

- `GATEWAY_PORTS` if "true" sshd will allow gateway ports
- `TCP_FORWARDING` if "true" sshd will allow TCP forwarding
- `DISABLE_SFTP` if "true" sshd will not accept sftp connections. Note: This does not
prevent file access unless you define a restricted shell for each user that prevents executing
programs that grant file access.

### Restricted Modes

The following three restricted modes, SFTP only, SCP only and Rsync only are mutually exclusive. If no mode is defined,
then all connection types will be accepted. Only one mode can be enabled at a time:

#### SFTP Only

- `SFTP_MODE` if "true" sshd will only accept sftp connections
- `SFTP_CHROOT` if in sftp only mode sftp will be chrooted to this directory. Default is user home directory (`%h`)

#### SCP Only

- `SCP_MODE` if "true" sshd will only accept scp connections (uses rssh)

#### Rsync Only

- `RSYNC_MODE` if "true" sshd will only accept rsync connections (uses rssh)

## SSH Host Keys

SSH uses host keys to identify the server. To avoid receiving a security warning the host keys should be mounted on an external volume.

By default this image will create new host keys in `/etc/ssh/keys` which should be mounted on an external volume. If you are using existing keys and they are mounted in `/etc/ssh` this image will use the default host key location making this image compatible with existing setups.

If you wish to configure SSH entirely with environment variables it is suggested that you externally mount `/etc/ssh/keys` instead of `/etc/ssh`.

## Authorized Keys

Mount your .ssh credentials (RSA public keys) at `/root/.ssh/` in order to
access the container via root which set `SSH_ENABLE_ROOT=true`. 
User's key mount in`/etc/authorized_keys/<username>` or set `authorized_keys` variable for each user in `/users.json` file.

Authorized keys must be either owned by root (uid/gid 0), or owned by the uid/gid that corresponds to the
uid/gid and user specified in `/users.json` file.

## SFTP mode

When in sftp only mode (activated by setting `SFTP_MODE=true`) the container will only accept sftp connections. All sftp actions will be chrooted to the `SFTP_CHROOT` directory which defaults to "/data".

Please note that all components of the pathname in the ChrootDirectory directive must be root-owned directories that are not writable by any other user or group (see `man 5 sshd_config`).

## SCP or Rsync modes

When in scp or rsync only mode (activated by setting `SCP_MODE=true` or `RSYNC_MODE=true` respectively) the container will only accept scp or rsync connections. No chroot is provided.

This is provided by using [rssh](http://www.pizzashack.org/rssh/) restricted shell.

## Custom Scripts

Executable shell scripts and binaries can be mounted or copied in to `/etc/entrypoint.d`. These will be run when the container is launched but before sshd is started. These can be used to customise the behaviour of the container.

## Password authentication

**Password authentication is not recommended** by using `SSH_ENABLE_PASSWORD_AUTH=true` environment variable you can enable password authentication. To do this you need provide pre-hash passwords by `password` variable in `/users.json` file.
To generate a hashed password use `mkpasswd` which is available in this image or use [https://trnubo.github.io/passwd.html](https://trnubo.github.io/passwd.html) to generate a hash in your browser.

```
docker run -ti -p 2222:22 \
  -v $(pwd)/users.json:/users.json \
  -e SSH_ENABLE_PASSWORD_AUTH=true \
  rafalmasiarek/sshd:latest
```

## Usage Example

The example below will run interactively and bind to port `2222` with default settings like disallow root login and disable authentication by password (accepted only ssh keys). 
```
docker run -ti -p 2222:22 \
  -v $(pwd)/keys/:/etc/authorized_keys \
  -v $(pwd)/users.json:/users.json
  rafalmasiareke/sshd:latest
```
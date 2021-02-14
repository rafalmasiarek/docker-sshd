#!/usr/bin/env bash

set -e

[ "$DEBUG" == 'true' ] && set -x

DAEMON=sshd

echo "> Starting SSHD"

# Copy default config from cache, if required
if [ ! "$(ls -A /etc/ssh)" ]; then
    cp -a /etc/ssh.cache/* /etc/ssh/
fi

set_hostkeys() {
    printf '%s\n' \
        'set /files/etc/ssh/sshd_config/HostKey[1] /etc/ssh/keys/ssh_host_rsa_key' \
        'set /files/etc/ssh/sshd_config/HostKey[2] /etc/ssh/keys/ssh_host_dsa_key' \
        'set /files/etc/ssh/sshd_config/HostKey[3] /etc/ssh/keys/ssh_host_ecdsa_key' \
        'set /files/etc/ssh/sshd_config/HostKey[4] /etc/ssh/keys/ssh_host_ed25519_key' \
    | augtool -s 1> /dev/null
}

print_fingerprints() {
    local BASE_DIR=${1-'/etc/ssh'}
    for item in dsa rsa ecdsa ed25519; do
        echo ">>> Fingerprints for ${item} host key"
        ssh-keygen -E md5 -lf ${BASE_DIR}/ssh_host_${item}_key
        ssh-keygen -E sha256 -lf ${BASE_DIR}/ssh_host_${item}_key
        ssh-keygen -E sha512 -lf ${BASE_DIR}/ssh_host_${item}_key
    done
}

check_authorized_key_ownership() {
    local file="$1"
    local _uid="$2"
    local _gid="$3"
    local uid_found="$(stat -c %u ${file})"
    local gid_found="$(stat -c %g ${file})"

    if ! ( [[ ( "$uid_found" == "$_uid" ) && ( "$gid_found" == "$_gid" ) ]] || [[ ( "$uid_found" == "0" ) && ( "$gid_found" == "0" ) ]] ); then
        echo "WARNING: Incorrect ownership for ${file}. Expected uid/gid: ${_uid}/${_gid}, found uid/gid: ${uid_found}/${gid_found}. File uid/gid must match from /users.json or be root owned."
    fi
}

# Generate Host keys, if required
if ls /etc/ssh/keys/ssh_host_* 1> /dev/null 2>&1; then
    echo ">> Found host keys in keys directory"
    set_hostkeys
    print_fingerprints /etc/ssh/keys
elif ls /etc/ssh/ssh_host_* 1> /dev/null 2>&1; then
    echo ">> Found Host keys in default location"
    # Don't do anything
    print_fingerprints
else
    echo ">> Generating new host keys"
    mkdir -p /etc/ssh/keys
    ssh-keygen -A
    mv /etc/ssh/ssh_host_* /etc/ssh/keys/
    set_hostkeys
    print_fingerprints /etc/ssh/keys
fi

# Fix permissions, if writable.
# NB ownership of /etc/authorized_keys are not changed
if [ -w ~/.ssh ]; then
    chown root:root ~/.ssh && chmod 700 ~/.ssh/
fi
if [ -w ~/.ssh/authorized_keys ]; then
    chown root:root ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi
if [ -w /etc/authorized_keys ]; then
    chown root:root /etc/authorized_keys
    chmod 755 /etc/authorized_keys
    # test for writability before attempting chmod
    for f in $(find /etc/authorized_keys/ -type f -maxdepth 1); do
        [ -w "${f}" ] && chmod 644 "${f}"
    done
fi

if [ -f "/users.json" ]; then
    USERADD_BIN=$(which useradd)
    jq -c '.[]' /users.json | while read i; do
        _UID=$(echo $i | jq -r  .uid)
        _GID=$(echo $i | jq -r  .gid)
        _NAME=$(echo $i | jq -r  .username)
        _SHELL=$(echo $i | jq -r  .shell)
        _PASSWORD=$(echo $i | jq -r  .password)
        _HOME=$(echo $i | jq -r  .home)
        _COMMENT=$(echo $i | jq -r .comment)
        _AUTHORIZED_KEYS=$(echo $i | jq -r .authorized_keys)

        if [[ ! -z "${_NAME}" && "${_NAME}" != "null" ]];
        then
            ADDUSER="$USERADD_BIN -r -m -p ''"
            message=">> Adding user ${_NAME}"
            if [[ ! -z "${_UID}" && "${_UID}" != "null" ]];
            then
                message="${message} with uid: ${_UID}"
                ADDUSER="$ADDUSER -u ${_UID}"
            fi
            if [[ ! -z "${_GID}" && "${_GID}" != "null" ]];
            then
                message="${message}, gid: ${_GID}"
                ADDUSER="$ADDUSER -g ${_GID}"
            fi
            if [[ ! -z "${_HOME}" && "${_HOME}" != "null" ]];
            then
                message="${message}, home: ${_HOME}"
                ADDUSER="$ADDUSER -d ${_HOME}"
            fi
            if [[ ! -z "${_SHELL}" && "${_SHELL}" != "null" ]];
            then
                message="${message}, shell: ${_SHELL}"
                ADDUSER="$ADDUSER -s ${_SHELL}"
            fi
            if [[ ! -z "${_COMMAND}" && "${_COMMAND}" != "null" ]];
            then
                message="${message}, comment: ${_COMMENT}"
                ADDUSER="$ADDUSER -c ${_COMMENT}"
            fi

            echo $message

            if [ ! -e "/etc/authorized_keys/${_NAME}" ];
            then
                if [[ ! -z "${_AUTHORIZED_KEYS}" && "${_AUTHORIZED_KEYS}" != "null" ]];
                then
                    echo -e "${_AUTHORIZED_KEYS}" > /etc/authorized_keys/${_NAME}
                    check_authorized_key_ownership /etc/authorized_keys/${_NAME} ${_UID} ${_GID}
                else
                    echo "WARNING: No SSH authorized_keys found for ${_NAME}!"
                fi
            else
                check_authorized_key_ownership /etc/authorized_keys/${_NAME} ${_UID} ${_GID}
            fi
            getent group ${_NAME} >/dev/null 2>&1 || groupadd -g ${_GID} ${_NAME}
            getent passwd ${_NAME} >/dev/null 2>&1 || $ADDUSER ${_NAME}

            if [[ ! -z "${_PASSWORD}" && "${_PASSWORD}" != "null" ]];
            then
                echo "${_NAME}:${_PASSWORD}" | chpasswd --encrypted
            fi
            # more paranoia
            if [[ ! -z "${_HOME}" && "${_HOME}" != "null" ]];
            then
                chmod 750 ${_HOME}
            fi
        fi
    done
else
    # Warn if no authorized_keys
    if [ ! -e ~/.ssh/authorized_keys ] && [ ! "$(ls -A /etc/authorized_keys)" ]; then
        echo "WARNING: No SSH authorized_keys found!"
    fi
fi

# Unlock root account, if enabled
if [[ "${SSH_ENABLE_ROOT}" == "true" ]]; then
    echo ">> Unlocking root account"
    usermod -p '' root
else
    echo "INFO: root account is now locked by default. Set SSH_ENABLE_ROOT to unlock the account."
fi

# Update MOTD
if [ -v MOTD ]; then
    echo -e "$MOTD" > /etc/motd
fi

# PasswordAuthentication (disabled by default)
if [[ "${SSH_ENABLE_PASSWORD_AUTH}" == "true" ]]; then
    echo 'set /files/etc/ssh/sshd_config/PasswordAuthentication yes' | augtool -s 1> /dev/null
    echo "WARNING: password authentication enabled."
else
    echo 'set /files/etc/ssh/sshd_config/PasswordAuthentication no' | augtool -s 1> /dev/null
    echo "INFO: password authentication is disabled by default. Set SSH_ENABLE_PASSWORD_AUTH=true to enable."
fi

configure_sftp_only_mode() {
    echo "INFO: configuring sftp only mode"
    : ${SFTP_CHROOT:="/home"}
    printf '%s\n' \
        'set /files/etc/ssh/sshd_config/Subsystem/sftp "internal-sftp"' \
        'set /files/etc/ssh/sshd_config/AllowTCPForwarding no' \
        'set /files/etc/ssh/sshd_config/GatewayPorts no' \
        'set /files/etc/ssh/sshd_config/X11Forwarding no' \
        'set /files/etc/ssh/sshd_config/ForceCommand internal-sftp' \
        "set /files/etc/ssh/sshd_config/ChrootDirectory ${SFTP_CHROOT}" \
    | augtool -s 1> /dev/null
    groupadd sftpuser
    if [ -f "/users.json" ]; then
        USERMOD_BIN=$(which usermod)
        jq -c '.[]' /users.json | while read i; do
            _NAME=$(echo $i | jq -r  .username)
            _HOME=$(echo $i | jq -r  .home)
            $USERMOD_BIN -s '/sbin/nologin' ${_NAME}
            $USERMOD_BIN -a -G sftpuser ${_NAME}
            if [[ ! -z "${_HOME}" && "${_HOME}" != "null" && "${_HOME}" != ${SFTP_CHROOT} ]];
            then
                chmod 700 ${_HOME}
            fi
        done
    fi
}

configure_scp_only_mode() {
    echo "INFO: configuring scp only mode"
    if [ -f "/users.json" ]; then
        USERMOD_BIN=$(which usermod)
        jq -c '.[]' /users.json | while read i; do
            _NAME=$(echo $i | jq -r  .username)
            $USERMOD_BIN -s '/usr/bin/rssh' ${_NAME}
        done
    fi
    (grep '^[a-zA-Z]' /etc/rssh.conf.default; echo "allowscp") > /etc/rssh.conf
}

configure_rsync_only_mode() {
    echo "INFO: configuring rsync only mode"
    if [ -f "/users.json" ]; then
        USERMOD_BIN=$(which usermod)
        jq -c '.[]' /users.json | while read i; do
            _NAME=$(echo $i | jq -r  .username)
            $USERMOD_BIN -s '/usr/bin/rssh' ${_NAME}
        done
    fi
    (grep '^[a-zA-Z]' /etc/rssh.conf.default; echo "allowrsync") > /etc/rssh.conf
}

configure_ssh_options() {
    # Enable AllowTcpForwarding
    if [[ "${TCP_FORWARDING}" == "true" ]]; then
        echo 'set /files/etc/ssh/sshd_config/AllowTcpForwarding yes' | augtool -s 1> /dev/null
    fi
    # Enable GatewayPorts
    if [[ "${GATEWAY_PORTS}" == "true" ]]; then
        echo 'set /files/etc/ssh/sshd_config/GatewayPorts yes' | augtool -s 1> /dev/null
    fi
    # Disable SFTP
    if [[ "${DISABLE_SFTP}" == "true" ]]; then
        printf '%s\n' \
            'rm /files/etc/ssh/sshd_config/Subsystem/sftp' \
            'rm /files/etc/ssh/sshd_config/Subsystem' \
        | augtool -s 1> /dev/null
    fi
}

# Configure mutually exclusive modes
if [[ "${SFTP_MODE}" == "true" ]]; then
    configure_sftp_only_mode
elif [[ "${SCP_MODE}" == "true" ]]; then
    configure_scp_only_mode
elif [[ "${RSYNC_MODE}" == "true" ]]; then
    configure_rsync_only_mode
else
    configure_ssh_options
fi

# Run scripts in /etc/entrypoint.d
for f in /etc/entrypoint.d/*; do
    if [[ -x ${f} ]]; then
        echo ">> Running: ${f}"
        ${f}
    fi
done

stop() {
    echo "Received SIGINT or SIGTERM. Shutting down $DAEMON"
    # Get PID
    local pid=$(cat /var/run/$DAEMON/$DAEMON.pid)
    # Set TERM
    kill -SIGTERM "${pid}"
    # Wait for exit
    wait "${pid}"
    # All done.
    echo "Done."
}

echo "Running $@"
if [ "$(basename $1)" == "$DAEMON" ]; then
    trap stop SIGINT SIGTERM
    $@ &
    pid="$!"
    mkdir -p /var/run/$DAEMON && echo "${pid}" > /var/run/$DAEMON/$DAEMON.pid
    wait "${pid}"
    exit $?
else
    exec "$@"
fi

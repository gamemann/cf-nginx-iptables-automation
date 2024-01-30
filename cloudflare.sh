#!/bin/bash
# General Configuration
BACKUP_DIR=./backups

# NGINX Configuration
NGINX_ENABLED=1
NGINX_RELOAD=0                          # Reloads NGINX after update if test is successful.
NGINX_BACKUP=1                          # Backups the current config to $BACKUP_DIR/$dateSimple.bak is appended.
NGINX_RESTORE=1                         # If NGINX test fails, will attempt to restore file.
NGINX_FILE=/etc/nginx/cloudflare.conf   # Path to the file to output CloudFlare configuration to. This should be the file included in your NGINX config.

# IPTables Configuration
IPTABLES_ENABLED=1
IPTABLES_CHAIN=cloudflare               # The name of the IPTables chain to add IP rules to.
IPTABLES_BACKUP=1                       # Backups output of `iptables-save`. 
IPTABLES_SAVE=1                         # Executes `netfilter-persistent save` when finished. You must have `iptables-persistent` package installed or something similar.
IPTABLES_MODE=0                         # Which mode to use. 0 = Flushes chain and re-adds all rules. > 0 = Scans output of `iptables -L <chain>` and if the IP range doesn't exist, adds it.

# Logging Configuration
LOG_DIR=./logs
LOG_FILE=$LOG_DIR/script.log

# Function to log messages to the log file
log() {
    echo "[`date +"%Y-%m-%d %H:%M:%S"`] $1" >> $LOG_FILE
}

# Create the log directory if it doesn't exist
mkdir -p $LOG_DIR

# Redirect all output to the log file
exec &>> $LOG_FILE

# Retrieve CloudFlare IPv4/IPv6 IPs.
ipv4=()
ipv6=()

log "Collecting IPs..."

for i in `curl -s -L https://www.cloudflare.com/ips-v4`; do
    ipv4+=("$i")

    log "IPv4: $i"
done

for i in `curl -s -L https://www.cloudflare.com/ips-v6`; do
    ipv6+=("$i")

    log "IPv6: $i"
done

# Make sure our arrays have at least one element.
if [ "${#ipv4[@]}" -lt 1 ]; then
    log "Found IPv4 array empty. Aborting..."

    exit 1
fi

if [ "${#ipv6[@]}" -lt 1 ]; then
    log "Found IPv6 array empty. Aborting..."

    exit 1
fi

# Retrieve current date.
dateSimple=$(date +"%Y-%m-%d-%H-%M")
dateMore=$(date +"%Y-%m-%d %H:%M:%S")

log "Starting script..."

# Attempt to make backup directory.
mkdir -p $BACKUP_DIR/

# IPTables.
if [ "$IPTABLES_ENABLED" -eq 1 ]; then
    log "[IPTables] Updating rules..."

    # Compile backup name.
    backupFile="iptables_$dateSimple.bak"

    # Check if we should backup.
    if [ "$IPTABLES_BACKUP" -eq 1 ]; then
        log "[IPTABLES] Performing backup..."

        iptables-save > $BACKUP_DIR/$backupFile
    fi

    # Make sure our chain is created.
    iptables -N $IPTABLES_CHAIN > /dev/null 2>&1
    ip6tables -N $IPTABLES_CHAIN > /dev/null 2>&1

    # Check what mode we're using.
    if [ "$IPTABLES_MODE" -eq 0 ]; then
        # We're using reset mode.
        log "[IPTABLES] Using mode reset..."

        # Flush chain.
        log "[IPTABLES] Flushing chain '$IPTABLES_CHAIN'..."

        iptables -F $IPTABLES_CHAIN
        ip6tables -F $IPTABLES_CHAIN

        # Add IPv4 rules.
        for i in "${ipv4[@]}"; do
            iptables -A $IPTABLES_CHAIN -s $i -p tcp -m conntrack --ctstate NEW,ESTABLISHED -m multiport --dport 80,443 -j ACCEPT
        done

        # Add IPv6 rules.
        for i in "${ipv6[@]}"; do
            ip6tables -A $IPTABLES_CHAIN -s $i -p tcp -m conntrack --ctstate NEW,ESTABLISHED -m multiport --dport 80,443 -j ACCEPT
        done
    else
        # We're using append mode.
        log "[IPTABLES] Using append mode..."

        outputV4=$(iptables -L $IPTABLES_CHAIN)
        outputV6=$(ip6tables -L $IPTABLES_CHAIN)

        # Add IPv4 rules.
        for i in "${ipv4[@]}"; do
            if ! echo "$outputV4" | grep -q "$i"; then
                log "[IPTABLES] Found new IPv4 range '$i'!"

                iptables -A $IPTABLES_CHAIN -s $i -p tcp -m conntrack --ctstate NEW,ESTABLISHED -m multiport --dport 80,443 -j ACCEPT
            fi
        done

        # Add IPv6 rules.
        for i in "${ipv6[@]}"; do
            if ! echo "$outputV6" | grep -q "$i"; then
                log "[IPTABLES] Found new IPv6 range '$i'!"

                ip6tables -A $IPTABLES_CHAIN -s $i -p tcp -m conntrack --ctstate NEW,ESTABLISHED -m multiport --dport 80,443 -j ACCEPT
            fi
        done
    fi

    # Check if we should save using netfilter.
    if [ "$IPTABLES_SAVE" -eq 1 ]; then
        log "[IPTABLES] Saving rules via Netfilter..."
        netfilter-persistent save
    fi
fi

# NGINX
if [ "$NGINX_ENABLED" -eq 1 ]; then
    log "[NGINX] Updating config..."

    # Compile backup name.
    backupFile="nginx_$dateSimple.bak"

    # Check if this is our first time (judging if $NGINX_FILE exists).
    if [ -e "$NGINX_FILE" ]; then
        # Check if we should backup old file.
        if [ "$NGINX_BACKUP" -eq 1 ]; then
            cp -f "$NGINX_FILE" "$BACKUP_DIR/$backupFile"
        fi
    fi

    # Start writing contents to NGINX file.
    echo "# Auto-Generated. Last Updated: $dateMore" > $NGINX_FILE
    echo "" >> $NGINX_FILE

    # Update IPv4 ranges.
    echo "# IPv4 Ranges" >> $NGINX_FILE

    for i in "${ipv4[@]}"; do
        echo "set_real_ip_from $i;" >> $NGINX_FILE 
    done

    echo "" >> $NGINX_FILE

    # Update IPv6 ranges.
    echo "# IPv6 Ranges" >> $NGINX_FILE

    for i in "${ipv6[@]}"; do
        echo "set_real_ip_from $i;" >> $NGINX_FILE
    done

    # Set real header.
    echo "" >> $NGINX_FILE
    echo "# Set Real Header" >> $NGINX_FILE
    echo "real_ip_header CF-Connecting-IP;" >> $NGINX_FILE;

    # We now want to test the NGINX config and check status.
    log "[NGINX] Testing config..."
    nginx -t

    if [ $? -ne 0 ]; then
        log "[NGINX] ERROR! Config did not test successfully!"

        # Check if we need to restore.
        if [ "$NGINX_RESTORE" -eq 1 ]; then
            log "[NGINX] Restoring from backup..."

            cp -f "$BACKUP_DIR/$backupFile" "$NGINX_FILE"

            log "[NGINX] Restored backup '$backupFile'. Testing again..."

            # Perform another test.
            nginx -t

            if [ $? -nq 0 ]; then
                log "[NGINX] ERROR! Test failed after attempting to restore. Manual investigation required..."
            else
                log "[NGINX] Restore and test successful!"
            fi
        fi
    else
        # Check if we should reload NGINX.
        if [ "$NGINX_RELOAD" -eq 1 ]; then
            log "[NGINX] Reloading NGINX server..."
            systemctl reload nginx
        fi
    fi
fi

log "Script completed successfully."

#!/bin/bash

LOG_FILE="/var/log/smtp/current"
TEMP_FILE="/tmp/qmail_auth_fails.txt"
BLOCK_FILE="/tmp/qmail_blocked_subnets.txt"
APF_CMD="/usr/local/sbin/apf"
BLOCK_DURATION=7200  # 2 hours
THRESHOLD=3          # 3 attempts
TIME_WINDOW=180      # 3 minutes
LOG="/var/log/qmail_block.log"

# Determine iptables command based on system configuration
if command -v iptables-legacy >/dev/null 2>&1; then
  IPTABLES_CMD="iptables-legacy"
else
  IPTABLES_CMD="iptables"
fi
echo "$(date) - Using $IPTABLES_CMD for iptables operations" >> "$LOG"

# Log script start
echo "$(date) - Script started" >> "$LOG" 2>> "$LOG"
if [ $? -ne 0 ]; then
  echo "Error: Cannot write to $LOG" >&2
  exit 1
fi

# Verify log file exists
if [ ! -f "$LOG_FILE" ]; then
  echo "$(date) - Error: Log file $LOG_FILE not found" >> "$LOG"
  exit 1
fi
echo "$(date) - Monitoring $LOG_FILE" >> "$LOG"

# Ensure temp and block files are writable
touch "$TEMP_FILE" || { echo "$(date) - Error: Cannot create $TEMP_FILE" >> "$LOG"; exit 1; }
touch "$BLOCK_FILE" || { echo "$(date) - Error: Cannot create $BLOCK_FILE" >> "$LOG"; exit 1; }

# Function to check and unblock expired subnets
check_unblocks() {
  current_time=$(date +%s)
  temp_block_file="/tmp/qmail_blocked_subnets_temp_$$.txt"
  touch "$temp_block_file"
  updated=false

  if [ -s "$BLOCK_FILE" ]; then
    while IFS=' ' read -r unblock_time subnet; do
      if [ -z "$unblock_time" ] || [ -z "$subnet" ]; then
        continue
      fi

      if [ "$unblock_time" -le "$current_time" ]; then
        $APF_CMD -u "$subnet" 2>> "$LOG"
        if [ $? -ne 0 ]; then
          echo "$(date) - Error unblocking $subnet with APF" >> "$LOG"
          echo "$unblock_time $subnet" >> "$temp_block_file"
        else
          echo "$(date) - Unblocked subnet: $subnet" >> "$LOG"
          updated=true
        fi
      else
        echo "$unblock_time $subnet" >> "$temp_block_file"
      fi
    done < "$BLOCK_FILE"
  fi

  if [ "$updated" = true ] || [ ! -s "$BLOCK_FILE" ]; then
    mv "$temp_block_file" "$BLOCK_FILE"
    echo "$(date) - Updated $BLOCK_FILE" >> "$LOG"
  else
    rm "$temp_block_file"
  fi
}

# Monitor log file
echo "$(date) - Starting tail -F on $LOG_FILE" >> "$LOG"
tail -F "$LOG_FILE" 2>> "$LOG" | grep --line-buffered "AUTH failed" 2>> "$LOG" | while read -r line; do
  echo "$(date) - Processing line: $line" >> "$LOG"

  # Check for unblocks
  check_unblocks

  # Extract IP
  ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
  if [ -n "$ip" ]; then
    current_time=$(date +%s)
    echo "$current_time $ip" >> "$TEMP_FILE"
    echo "$(date) - Recorded AUTH failed from $ip" >> "$LOG"

    # Clean old entries
    awk -v now="$current_time" -v window="$TIME_WINDOW" '$1 > (now - window)' "$TEMP_FILE" > "$TEMP_FILE.tmp" && mv "$TEMP_FILE.tmp" "$TEMP_FILE"

    # Count attempts
    attempts=$(grep -c "$ip" "$TEMP_FILE")
    echo "$(date) - $ip has $attempts attempts in last $TIME_WINDOW seconds" >> "$LOG"

    # Block the /24 subnet if threshold exceeded
    if [ "$attempts" -ge "$THRESHOLD" ]; then
      subnet="${ip%.*}.0/24"

      # Check APF deny file instead of iptables for consistency
      if ! grep -q "$subnet" /etc/spf/deny_hosts.rules 2>/dev/null; then
        $APF_CMD -d "$subnet" "qmail AUTH failed from $ip" 2>> "$LOG"
        if [ $? -ne 0 ]; then
          echo "$(date) - Error blocking $subnet with APF" >> "$LOG"
        else
          echo "$(date) - Blocked subnet: $subnet for $BLOCK_DURATION seconds" >> "$LOG"
          unblock_time=$((current_time + BLOCK_DURATION))
          echo "$unblock_time $subnet" >> "$BLOCK_FILE"
          sed -i "/$ip/d" "$TEMP_FILE"
        fi
      else
        echo "$(date) - $subnet already exists in /etc/spf/deny_hosts.rules" >> "$LOG"
      fi
    fi
  else
    echo "$(date) - Warning: No IP found in line: $line" >> "$LOG"
  fi
done

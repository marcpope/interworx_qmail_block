#!/bin/bash

LOG_FILE="/var/log/smtp/current"
TEMP_FILE="/tmp/qmail_auth_fails.txt"
BLOCK_FILE="/tmp/qmail_blocked_subnets.txt"
APF_CMD="/usr/local/sbin/apf"
BLOCK_DURATION=7200  # 2 hours
THRESHOLD=3          # 3 attempts
TIME_WINDOW=180      # 3 minutes
LOG="/var/log/qmail_block.log"
CHECK_INTERVAL=5     # Minimum seconds between unblock checks

# Determine iptables command
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

# Track last check time
LAST_CHECK_FILE="/tmp/qmail_last_check.txt"
[ -f "$LAST_CHECK_FILE" ] || echo "0" > "$LAST_CHECK_FILE"

# Function to check and unblock expired subnets
check_unblocks() {
  current_time=$(date +%s)
  last_check=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "0")

  if [ $((current_time - last_check)) -lt "$CHECK_INTERVAL" ]; then
    echo "$(date) - Skipping check_unblocks: too soon (last check at $last_check)" >> "$LOG"
    return 0
  fi
  echo "$current_time" > "$LAST_CHECK_FILE"

  echo "$(date) - Starting check_unblocks at $current_time" >> "$LOG"
  temp_block_file="/tmp/qmail_blocked_subnets_temp_$$.txt"
  touch "$temp_block_file" || { echo "$(date) - Error: Cannot create $temp_block_file" >> "$LOG"; return 1; }

  echo "$(date) - Current $BLOCK_FILE contents:" >> "$LOG"
  cat "$BLOCK_FILE" >> "$LOG" 2>/dev/null || echo "$(date) - Failed to read $BLOCK_FILE" >> "$LOG"

  if [ -s "$BLOCK_FILE" ]; then
    changed=false
    while IFS=' ' read -r unblock_time subnet; do
      if [ -z "$unblock_time" ] || [ -z "$subnet" ]; then
        echo "$(date) - Skipping empty/malformed line: '$unblock_time $subnet'" >> "$LOG"
        continue
      fi

      echo "$(date) - Processing unblock entry: $unblock_time $subnet" >> "$LOG"
      if [ "$unblock_time" -le "$current_time" ]; then
        echo "$(date) - Attempting to unblock $subnet" >> "$LOG"
        $APF_CMD -u "$subnet" >> "$LOG" 2>&1
        if [ $? -ne 0 ]; then
          echo "$(date) - Error unblocking $subnet with APF" >> "$LOG"
          echo "$unblock_time $subnet" >> "$temp_block_file"
        else
          echo "$(date) - Successfully unblocked $subnet" >> "$LOG"
          changed=true
        fi
      else
        echo "$unblock_time $subnet" >> "$temp_block_file"
      fi
    done < "$BLOCK_FILE"

    if [ "$changed" = true ]; then
      echo "$(date) - Writing new $BLOCK_FILE" >> "$LOG"
      mv -f "$temp_block_file" "$BLOCK_FILE" 2>> "$LOG"
      if [ $? -eq 0 ]; then
        echo "$(date) - Successfully updated $BLOCK_FILE" >> "$LOG"
        echo "$(date) - New $BLOCK_FILE contents:" >> "$LOG"
        cat "$BLOCK_FILE" >> "$LOG" 2>/dev/null || echo "$(date) - Failed to read updated $BLOCK_FILE" >> "$LOG"
      else
        echo "$(date) - Error: Failed to update $BLOCK_FILE" >> "$LOG"
        rm -f "$temp_block_file"
        return 1
      fi
    else
      echo "$(date) - No changes needed in $BLOCK_FILE" >> "$LOG"
      rm -f "$temp_block_file"
    fi
  else
    echo "$(date) - $BLOCK_FILE is empty or does not exist" >> "$LOG"
    rm -f "$temp_block_file"
  fi
  echo "$(date) - Finished check_unblocks" >> "$LOG"
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
      if grep -q "$subnet" /etc/apf/deny_hosts.rules 2>/dev/null; then
        echo "$(date) - $subnet already exists in /etc/apf/deny_hosts.rules, skipping block" >> "$LOG"
      else
        echo "$(date) - Attempting to block $subnet" >> "$LOG"
        $APF_CMD -d "$subnet" "qmail AUTH failed from $ip" >> "$LOG" 2>&1
        if [ $? -eq 0 ]; then
          echo "$(date) - Blocked subnet: $subnet for $BLOCK_DURATION seconds" >> "$LOG"
          unblock_time=$((current_time + BLOCK_DURATION))
          echo "$unblock_time $subnet" >> "$BLOCK_FILE"
          sed -i "/$ip/d" "$TEMP_FILE"
        else
          echo "$(date) - Error blocking $subnet with APF" >> "$LOG"
        fi
      fi
    fi
  else
    echo "$(date) - Warning: No IP found in line: $line" >> "$LOG"
  fi
done

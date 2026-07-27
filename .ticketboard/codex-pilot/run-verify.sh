#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: run-verify.sh <baseline|validation> <repository> <private-home>" >&2
  exit 64
fi

profile="$1"
repository_path="$2"
private_home="$3"
verify_user="ticketboard-verify"
max_runtime_seconds="180"
max_processes="256"
max_file_kib="8388608"
max_virtual_memory_kib="4194304"
max_open_files="512"
max_disk_bytes="8589934592"

case "$profile:$repository_path:$private_home" in
  "baseline:$RUNNER_TEMP/ticketboard-baseline/repository:$RUNNER_TEMP/ticketboard-baseline/home") ;;
  "validation:$RUNNER_TEMP/ticketboard-validation/repository:$RUNNER_TEMP/ticketboard-validation/home") ;;
  *)
    echo "verification paths do not match the closed trusted profile" >&2
    exit 65
    ;;
esac

for required_directory in "$repository_path" "$private_home"; do
  if [[ ! -d "$required_directory" || -L "$required_directory" ]]; then
    echo "verification boundary must be a regular directory" >&2
    exit 66
  fi
done

for required_command in systemd-run systemctl timeout unshare npm du; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "required verification boundary command is unavailable" >&2
    exit 69
  fi
done
if ! id -u "$verify_user" >/dev/null 2>&1; then
  echo "verification user is unavailable" >&2
  exit 69
fi
if [[ ! "$GITHUB_RUN_ID" =~ ^[0-9]+$ ||
      ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
  echo "GitHub execution identity is invalid" >&2
  exit 69
fi

unit_name="ticketboard-${profile}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
resource_exceeded="false"
service_pid=""

stop_service() {
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    sudo systemctl kill --signal=KILL "${unit_name}.service" \
      >/dev/null 2>&1 || true
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  sudo pkill -KILL -u "$verify_user" >/dev/null 2>&1 || true
}
trap stop_service EXIT

sudo install -d -m 700 -o "$verify_user" -g "$verify_user" \
  "$private_home/tmp"

sudo systemd-run \
  --quiet \
  --wait \
  --collect \
  --pipe \
  --service-type=exec \
  --unit="$unit_name" \
  --property="User=$verify_user" \
  --property="Group=$verify_user" \
  --property="WorkingDirectory=$repository_path" \
  --property="CPUAccounting=yes" \
  --property="CPUQuota=200%" \
  --property="MemoryAccounting=yes" \
  --property="MemoryMax=4096M" \
  --property="MemorySwapMax=0" \
  --property="TasksAccounting=yes" \
  --property="TasksMax=$max_processes" \
  --property="LimitNPROC=$max_processes" \
  --property="LimitNOFILE=$max_open_files" \
  --property="LimitFSIZE=8192M" \
  --property="LimitAS=4096M" \
  --property="LimitCPU=$max_runtime_seconds" \
  --property="RuntimeMaxSec=$max_runtime_seconds" \
  --property="PrivateNetwork=yes" \
  --property="NoNewPrivileges=yes" \
  --property="PrivateDevices=yes" \
  --property="ProtectControlGroups=yes" \
  --property="ProtectKernelModules=yes" \
  --property="ProtectKernelTunables=yes" \
  --property="RestrictSUIDSGID=yes" \
  --setenv="PATH=/opt/hostedtoolcache/node/24.18.0/x64/bin:/usr/local/bin:/usr/bin:/bin" \
  --setenv="HOME=$private_home" \
  --setenv="TMPDIR=$private_home/tmp" \
  --setenv="LANG=C.UTF-8" \
  --setenv="CI=true" \
  --setenv="NO_PROXY=*" \
  --setenv="no_proxy=*" \
  --setenv="npm_config_audit=false" \
  --setenv="npm_config_fund=false" \
  --setenv="GIT_CONFIG_GLOBAL=/dev/null" \
  --setenv="GIT_CONFIG_SYSTEM=/dev/null" \
  --setenv="GIT_CONFIG_NOSYSTEM=1" \
  --setenv="GIT_OPTIONAL_LOCKS=0" \
  --setenv="GIT_TERMINAL_PROMPT=0" \
  /usr/bin/bash -c '
    set -euo pipefail
    ulimit -u "$1"
    ulimit -f "$2"
    ulimit -v "$3"
    ulimit -n "$4"
    ulimit -t "$5"
    exec /usr/bin/timeout --signal=TERM --kill-after=15s "${5}s" \
      /usr/bin/unshare --user --map-root-user --net --mount-proc \
      npm run verify
  ' phase7d-resource-boundary \
  "$max_processes" "$max_file_kib" "$max_virtual_memory_kib" \
  "$max_open_files" "$max_runtime_seconds" &
service_pid="$!"

while kill -0 "$service_pid" 2>/dev/null; do
  disk_bytes="$(
    sudo du --apparent-size --block-size=1 --summarize \
      "$repository_path" "$private_home" 2>/dev/null |
      awk '{ total += $1 } END { print total + 0 }'
  )"
  if [[ ! "$disk_bytes" =~ ^[0-9]+$ ||
        "$disk_bytes" -gt "$max_disk_bytes" ]]; then
    resource_exceeded="true"
    sudo systemctl kill --signal=KILL "${unit_name}.service" \
      >/dev/null 2>&1 || true
    break
  fi
  sleep 2
done

set +e
wait "$service_pid"
service_status="$?"
set -e
service_pid=""
if [[ "$resource_exceeded" == "true" ]]; then
  echo "verification disk boundary exceeded" >&2
  exit 75
fi
exit "$service_status"

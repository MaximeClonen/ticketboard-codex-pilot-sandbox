#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
  echo "usage: run-codex.sh <repo> <prompt> <schema> <jsonl> <result> <codex-home>" >&2
  exit 64
fi

repository_path="$1"
prompt_path="$2"
schema_path="$3"
jsonl_path="$4"
result_path="$5"
codex_home="$6"
codex_user="codex-pilot"
codex_bin="$(command -v codex)"
timeout_bin="$(command -v timeout)"
systemd_run_bin="$(command -v systemd-run)"
systemctl_bin="$(command -v systemctl)"
du_bin="$(command -v du)"
max_runtime_seconds="900"
max_processes="256"
max_file_kib="8388608"
max_virtual_memory_kib="4194304"
max_open_files="512"
max_disk_bytes="8589934592"
codex_bin_dir="$(dirname "$codex_bin")"

case "$repository_path" in
  "$GITHUB_WORKSPACE") ;;
  *)
    echo "repository path must be the exact GitHub workspace" >&2
    exit 65
    ;;
esac
if [[ ! "$GITHUB_RUN_ID" =~ ^[0-9]+$ ||
      ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
  echo "GitHub execution identity is invalid" >&2
  exit 65
fi

for required_file in "$prompt_path" "$schema_path"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    echo "trusted Codex input is missing or not a regular file" >&2
    exit 66
  fi
done
for required_command in \
  "$codex_bin" "$timeout_bin" "$systemd_run_bin" "$systemctl_bin" "$du_bin"; do
  if [[ ! -x "$required_command" ]]; then
    echo "required Codex boundary command is unavailable" >&2
    exit 69
  fi
done

git_directory="$repository_path/.git"
if [[ ! -d "$git_directory" || -L "$git_directory" ]]; then
  echo "repository .git boundary must be a regular directory" >&2
  exit 67
fi
runner_uid="$(id -u)"
runner_gid="$(id -g)"
repository_mode="$(stat -c '%a' "$repository_path")"
unit_name="ticketboard-codex-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
service_pid=""
resource_exceeded="false"

umask 077
mkdir -p "$(dirname "$jsonl_path")" "$(dirname "$result_path")"
touch "$jsonl_path" "$result_path"
chmod 600 "$jsonl_path" "$result_path"
sudo install -d -m 700 -o "$codex_user" -g "$codex_user" \
  "$codex_home" "$codex_home/tmp"

# The worktree is writable, but .git remains runner-owned and is protected by
# a sticky repository root so the model user cannot replace the .git entry.
sudo chown -R "$runner_uid:$runner_gid" "$git_directory"
sudo chmod -R go-w "$git_directory"
sudo chown "$runner_uid:$runner_gid" "$repository_path"
sudo chgrp "$codex_user" "$repository_path"
sudo chmod 1770 "$repository_path"
sudo find "$repository_path" -mindepth 1 -maxdepth 1 ! -name .git \
  -exec chown -R "$codex_user:$codex_user" {} +
sudo chown "$codex_user:$codex_user" "$result_path"

for protected_path in \
  "$git_directory" \
  "$git_directory/config" \
  "$git_directory/index" \
  "$git_directory/refs" \
  "$git_directory/hooks"; do
  if [[ -e "$protected_path" ]] &&
    sudo -u "$codex_user" -- test -w "$protected_path"; then
    echo "model user can write protected .git state" >&2
    exit 68
  fi
done

measure_disk_bytes() {
  local attempt output status
  for attempt in 1 2 3; do
    set +e
    output="$(
      sudo "$du_bin" --apparent-size --block-size=1 --summarize \
        "$repository_path" "$codex_home" "$jsonl_path" "$result_path" \
        2>/dev/null |
        awk '{ total += $1 } END { print total + 0 }'
    )"
    status="$?"
    set -e
    if [[ "$status" -eq 0 && "$output" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$output"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

stop_service() {
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    sudo "$systemctl_bin" kill --signal=KILL "${unit_name}.service" \
      >/dev/null 2>&1 || true
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  sudo pkill -KILL -u "$codex_user" >/dev/null 2>&1 || true
}

restore_runner_ownership() {
  stop_service
  sudo find "$repository_path" -mindepth 1 -maxdepth 1 ! -name .git \
    -exec chown -R "$runner_uid:$runner_gid" {} + || true
  sudo chown "$runner_uid:$runner_gid" "$repository_path" || true
  sudo chmod "$repository_mode" "$repository_path" || true
  sudo chown -R "$runner_uid:$runner_gid" "$codex_home" || true
  sudo chown "$runner_uid:$runner_gid" "$result_path" || true
}
trap restore_runner_ownership EXIT

# The official action has already installed Codex and started its credential
# proxy. The model process receives an explicit environment and hard transient
# cgroup limits. Generated commands retain the reviewed workspace-only profile.
sudo "$systemd_run_bin" \
  --quiet \
  --wait \
  --collect \
  --pipe \
  --service-type=exec \
  --unit="$unit_name" \
  --property="User=$codex_user" \
  --property="Group=$codex_user" \
  --property="WorkingDirectory=$repository_path" \
  --property="UMask=0077" \
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
  --property="NoNewPrivileges=yes" \
  --property="PrivateDevices=yes" \
  --property="ProtectControlGroups=yes" \
  --property="ProtectKernelModules=yes" \
  --property="ProtectKernelTunables=yes" \
  --property="RestrictSUIDSGID=yes" \
  --setenv="HOME=/home/$codex_user" \
  --setenv="CODEX_HOME=$codex_home" \
  --setenv="TMPDIR=$codex_home/tmp" \
  --setenv="LANG=C.UTF-8" \
  --setenv="PATH=$codex_bin_dir:/usr/local/bin:/usr/bin:/bin" \
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
    shift 5
    exec "$@"
  ' phase7d-resource-boundary \
  "$max_processes" "$max_file_kib" "$max_virtual_memory_kib" \
  "$max_open_files" "$max_runtime_seconds" \
  "$timeout_bin" --signal=TERM --kill-after=15s \
  "${max_runtime_seconds}s" \
  "$codex_bin" exec \
  --json \
  --ephemeral \
  --ignore-user-config \
  --ignore-rules \
  --output-schema "$schema_path" \
  --output-last-message "$result_path" \
  --model "gpt-5.6-sol" \
  -c 'approval_policy="never"' \
  -c 'default_permissions=":workspace"' \
  -C "$repository_path" \
  - <"$prompt_path" >"$jsonl_path" &
service_pid="$!"

while kill -0 "$service_pid" 2>/dev/null; do
  if ! disk_bytes="$(measure_disk_bytes)" ||
    [[ "$disk_bytes" -gt "$max_disk_bytes" ]]; then
    resource_exceeded="true"
    sudo "$systemctl_bin" kill --signal=KILL "${unit_name}.service" \
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
  echo "Codex disk boundary exceeded" >&2
  exit 75
fi
exit "$service_status"

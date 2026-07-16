#!/usr/bin/env python3
"""Apply wallet production-safety patches to the upstream dstack-cloud CLI.

The current CLI is test-oriented: it shells out to gsutil, attaches the
project's default service account, accepts only ephemeral IPs, and deletes the
state disk with the VM. This idempotent patch changes only those deployment
mechanics; it does not alter measured guest artifacts.
"""
from pathlib import Path
import sys

path = Path(sys.argv[1] if len(sys.argv) > 1 else "~/.local/bin/dstack-cloud").expanduser()
s = path.read_text()

s = s.replace('cmd = ["gsutil"] + args', 'cmd = ["gcloud", "storage"] + args')

# Preserve the wallet SQLite disk across instance replacement.
s = s.replace(
    'f"--create-disk=name={config.instance_name}-data,size={config.data_size}GB,type=pd-balanced,image={data_image},auto-delete=yes",',
    'data_disk_arg,',
)

needle = '''        create_args = [
            "compute", "instances", "create", config.instance_name,'''
if 'data_disk_arg =' not in s:
    replacement = '''        data_disk_name = f"{config.instance_name}-data"
        existing_data_disk = self._run_gcloud([
            "compute", "disks", "describe", data_disk_name,
            f"--zone={config.zone}", f"--project={config.project}",
        ], check=False)
        if existing_data_disk.returncode == 0:
            data_disk_arg = (
                f"--disk=name={data_disk_name},device-name=data,mode=rw,"
                "boot=no,auto-delete=no"
            )
            logger.info(f"Reusing durable data disk: {data_disk_name}")
        else:
            data_disk_arg = (
                f"--create-disk=name={data_disk_name},size={config.data_size}GB,"
                f"type=pd-balanced,image={data_image},auto-delete=no"
            )

        create_args = [
            "compute", "instances", "create", config.instance_name,'''
    if needle not in s:
        raise SystemExit('could not find instance create block')
    s = s.replace(needle, replacement)

# Never grant the measured CVM a cloud identity unless explicitly configured.
needle = '''        if config.service_account:
            create_args.append(f"--service-account={config.service_account}")
        if config.scopes:
            create_args.append(f"--scopes={','.join(config.scopes)}")'''
replacement = '''        if config.service_account:
            create_args.append(f"--service-account={config.service_account}")
            if config.scopes:
                create_args.append(f"--scopes={','.join(config.scopes)}")
        else:
            create_args.extend(["--no-service-account", "--no-scopes"])
        if __import__("os").environ.get("DSTACK_GCP_ADDRESS"):
            create_args.append(
                f"--address={__import__('os').environ['DSTACK_GCP_ADDRESS']}"
            )'''
if needle in s:
    s = s.replace(needle, replacement)
elif 'DSTACK_GCP_ADDRESS' not in s:
    raise SystemExit('could not find service-account block')

path.write_text(s)
print(f"patched {path}")

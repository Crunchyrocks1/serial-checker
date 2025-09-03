import platform
import subprocess
import uuid
import os
import sys
import ctypes


class Colors:
    RED = "\033[91m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def run_as_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)


def run_cmd(cmd):
    try:
        out = subprocess.check_output(
            cmd, shell=True, text=True, stderr=subprocess.STDOUT
        ).strip().splitlines()
        return [line.strip() for line in out if line.strip()]
    except subprocess.CalledProcessError as e:
        return [e.output.strip()] if e.output else ["Not Available"]
    except:
        return ["Not Available"]


def get_secure_boot():
    try:
        result = subprocess.check_output(
            'powershell -command "Confirm-SecureBootUEFI"',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        if not result:
            return "Not Supported"
        if "not supported" in result.lower():
            return "Not Supported"
        if result.lower() == "true":
            return "Enabled"
        if result.lower() == "false":
            return "Disabled"
        return result
    except subprocess.CalledProcessError as e:
        if "not supported" in e.output.lower():
            return "Not Supported"
        return "Not Available"
    except:
        return "Not Available"


def get_tpm_info():
    try:
        present = subprocess.check_output(
            'powershell -command "(Get-Tpm).TpmPresent"',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        ready = subprocess.check_output(
            'powershell -command "(Get-Tpm).TpmReady"',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        enabled = subprocess.check_output(
            'powershell -command "(Get-Tpm).TpmEnabled"',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()

        def fmt(val):
            if val.lower() == "true": return "Yes"
            if val.lower() == "false": return "No"
            return val

        return fmt(present), fmt(ready), fmt(enabled)
    except subprocess.CalledProcessError:
        return "Not Supported", "Not Supported", "Not Supported"
    except:
        return "Not Available", "Not Available", "Not Available"


def get_directx_version():
    try:
        result = subprocess.check_output(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\DirectX" /v Version',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        for line in result.splitlines():
            if "Version" in line:
                return line.split()[-1]
        return "Not Found"
    except:
        return "Not Available"


def get_dotnet_versions():
    try:
        result = subprocess.check_output(
            'dotnet --list-runtimes',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        if not result:
            return "Not Installed"
        runtimes = result.splitlines()
        has_net9 = any("Microsoft.NETCore.App 9." in r for r in runtimes)
        return "Installed (.NET 9 found)" if has_net9 else "Installed (❌ .NET 9 not found)"
    except:
        return "Not Installed"


def get_total_ram():
    try:
        result = subprocess.check_output(
            'wmic computersystem get TotalPhysicalMemory /value',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        total_bytes = int(result.split("=")[-1])
        return f"{round(total_bytes / (1024**3))} GB"
    except:
        return "Not Available"

def get_gpu_vendor():
    try:
        result = run_cmd("wmic path win32_VideoController get Name")
        gpus = [r for r in result if r.lower() not in ["name", ""]]
        if not gpus:
            return "Not Found"

        vendors = []
        for g in gpus:
            g = g.lower()
            if "nvidia" in g:
                vendors.append("NVIDIA")
            elif "amd" in g or "radeon" in g:
                vendors.append("AMD")
            elif "intel" in g:
                vendors.append("Intel")
            else:
                vendors.append(g.title())
        return ", ".join(sorted(set(vendors)))
    except:
        return "Not Available"


def get_virtualization():
    try:
        result = subprocess.check_output(
            'systeminfo',
            shell=True, text=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore"
        )

        virt_info = {}
        for line in result.splitlines():
            if ":" in line and ("Hyper-V" in line or "Virtualization" in line):
                key, val = line.split(":", 1)
                virt_info[key.strip()] = val.strip()

        return virt_info if virt_info else {"Virtualization": "Not Supported"}
    except:
        return {"Virtualization": "Not Available"}




def get_boot_mode():
    try:
        result = subprocess.check_output(
            'bcdedit',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        if "path                    \EFI" in result:
            return "UEFI"
        return "Legacy BIOS"
    except:
        return "Not Available"


def collect_system_info():
    bios_vendor = run_cmd('wmic bios get manufacturer /value')[-1].split('=')[-1]
    bios_version = run_cmd('wmic bios get smbiosbiosversion /value')[-1].split('=')[-1]
    bios_date = run_cmd('wmic bios get releasedate /value')[-1].split('=')[-1]

    secure_boot = get_secure_boot()
    tpm_present, tpm_ready, tpm_enabled = get_tpm_info()
    directx = get_directx_version()
    dotnet = get_dotnet_versions()
    ram = get_total_ram()
    gpu_vendor = get_gpu_vendor()
    virt = get_virtualization()
    boot_mode = get_boot_mode()

    info = {
        "Windows Edition": platform.platform(),
        "Windows Build": platform.version(),
        "Windows HWID": run_cmd('wmic os get serialnumber /value')[-1].split('=')[-1],
        "BIOS UUID": run_cmd('wmic csproduct get uuid /value')[-1].split('=')[-1],
        "Motherboard Serial": run_cmd('wmic baseboard get serialnumber /value')[-1].split('=')[-1],
        "Processor ID": run_cmd('wmic cpu get processorid /value')[-1].split('=')[-1],
        "CPU Name": platform.processor(),
        "CPU Cores": os.cpu_count(),
        "Architecture": platform.machine(),
        "RAM Installed": ram,
        "GPU Vendor": gpu_vendor,
        "Disk Model": run_cmd('wmic diskdrive get model /value')[-1].split('=')[-1],
        "Disk Serial": run_cmd('wmic diskdrive get serialnumber /value')[-1].split('=')[-1],
        "MAC Address": ':'.join(
            [f"{(uuid.getnode() >> ele) & 0xff:02x}" for ele in range(40, -8, -8)]
        ),
        "BIOS Vendor": bios_vendor,
        "BIOS Version": bios_version,
        "BIOS Date": bios_date,
        "Boot Mode": boot_mode,
        "Secure Boot": secure_boot,
        "TPM Present": tpm_present,
        "TPM Ready": tpm_ready,
        "TPM Enabled": tpm_enabled,
        "DirectX Version": directx,
        ".NET Runtime": dotnet,
    }

    for k, v in virt.items():
        info[k] = v

    return info


def main():
    os.system("cls")
    print(Colors.RED + Colors.BOLD + "="*60)
    print("           SYSTEM COMPATIBILITY CHECK ")
    print("="*60 + Colors.RESET)

    info = collect_system_info()

    for key, val in info.items():
        print(f"{Colors.WHITE}{key:<20}{Colors.RED}: {Colors.GRAY}{val}{Colors.RESET}")

    input(Colors.GRAY + "Press any key to exit..." + Colors.RESET)


if __name__ == "__main__":
    run_as_admin()
    main()

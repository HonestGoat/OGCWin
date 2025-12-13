# 🛠️ OGCWin – The easy to use Windows Utility for Windows 11 Users and Gamers 🎮

🛠️ **Work in Progress:**
OGCWin is still being actively developed. It is currently functional, but some features break as Microsoft tries to stop people removing AI and data collection features in Windows 11.
More features and improvements are on the way! 🚀

OGC Windows Utility is an all-in-one tool designed to help Windows users setup, debloat, optimise, troubleshoot, repair, and enhance their system with ease.
Built from decades of experience as a Systems Engineer and PC Technician, this utility brings together my best scripts into a lightweight, user-friendly text-based utility.

Originally developed for the **Oceanic Gaming Community Discord**, OGCWin is now available for everyone who wants to improve their Windows experience effortlessly.

🚀 **Whether you’re setting up a new PC, a fresh Windows installation, or optimising an existing system, OGCWin simplifies the process.**

---

## 🔥 Current Features

✅ **Debloat Windows** – Remove unnecessary bloatware for a leaner, faster system.  
✅ **Privacy Enhancements** – Disable Windows telemetry, tracking, and data collection.  
✅ **Gaming Optimisations** – Tune Windows settings for improved gaming performance.  
✅ **Automated Software Installation** – Install essential apps, game launchers, and utilities with one click.  
✅ **System Troubleshooting & Repair** – Diagnose and fix common Windows issues automatically.  
✅ **New PC Setup Wizard** – A step-by-step guide to optimising a new PC or fresh Windows installation.  
✅ **Easy to Use** – No tech knowledge required—just run the tool and follow the prompts.

---

## 🚀 Installation & First-Time Setup

To install and run OGCWin for the first time, right-click on the Start button and open **PowerShell (Admin)** in Windows 10 or **Terminal (Admin)** in Windows 11 and run the following command:

```ps1
irm ogc.win | iex
```

🔹 **What Happens Next?** OGCWin will automatically download and set up everything needed. A shortcut will be created on your Desktop, allowing you to launch the utility anytime with a double-click. After the first run, simply use the shortcut to start OGCWin. No need to re-enter the command.

### 🎯 How It Works

1️⃣ **Launch OGCWin** using the desktop shortcut or PowerShell command.

2️⃣ **Choose your Mode:**
* **Wizard Mode:** Guides you step-by-step through setting up a new PC or fresh Windows installation.
* **Utility Mode:** Gives you direct access to powerful tools for debloating, optimising, troubleshooting, and repairing your system.

3️⃣ **Follow the on-screen prompts** to apply tweaks, install apps, or fix system issues.

### 📥 Supported Windows Versions

✅ **Windows 11** Home & Pro versions are fully supported.  
🚧 **Windows 10** is end of life and is currently partially supported by this utility. I am currently working on repairing and incorporating Windows 10 functions back into the Utility.

---

## 🚀 Upcoming Features
Some of these features will be implemented quickly, others will be a while. I'm one man and I have other projects that take priority.

**🔄 Backup, Migration & Recovery**
* **PC Transfer Wizard:** PC backup and restore wizards to make transferring or reinstalling PCs quick and easy.
* **High Speed Backups + NAS Integration:** Incorporating RoboCopy for multithreaded backups and copying to local/network storage.
* **Unified Archiving:** Compress Outlook and Save backups into single archive files for easier storage.
* **Additional Wizard Integrations:** 'Restore Backups' step will be added to the OGC New Installation Wizard once backup/restore functions complete.
* **Enhanced Uninstaller:** Custom uninstaller that removes the utility but preserves user profiles and backup files.

**🛠 System Repair & Maintenance**
* **Restore Point Management:** Easily create and manage system restore points.
* **Automated Health Check:** One-click automation for `SFC` and `DISM RestoreHealth` to fix system file corruption.
* **Update Fixer:** Automated tool to clear the Windows Update cache and restart services to fix stuck updates.
* **Disk Health and Repair Tools:** Wrappers for `Check Disk`, `fsutil`, and `bcdedit` (with reboot scheduling) and NTFS self-healing commands.
* **Network Reset:** Automation of flush DNS, reset Winsock, and renew IP configurations in one go.

**⚡ Performance & Tweaks**
* **Office Debloat:** Automated tool to roll back Office 365 and disable updates to permanently remove Copilot from MS Office.
* **Legacy App Tuning:** Toggle the 3GB RAM switch (`IncreaseUserVA`) for older Win32 applications.
* **File System Upgrades:** Enable Long Pathname support in Windows Registry.
* **Security and Gaming Performance Tweaks:** Toggle Memory Isolation and manage BitLocker status.

**🖥️ Desktop & Power Management**
* **Desktop Layouts:** Save and restore desktop icon positions with custom named layouts.
* **Power Profile Portability:** Export and import Windows Power Plans.
* **Diagnostics:** Generate detailed Power/Battery Usage and Sleep Study reports.
* **USB Control:** Disable USB Selective Suspend (Windows 11) to prevent device dropouts.
* **Bios Reboot:** Quick shortcut to restart directly into the system BIOS/UEFI.

---

## 🔗 Join the Community!
Need help, have suggestions, or just want to chat with other gamers? Join the Oceanic Gaming Community Discord!

[👉 Join the OGC Discord Server](https://discord.gg/ogc)

💡 **Want to contribute or report an issue?** Open a GitHub issue or join the Discord to discuss!

⭐ **Support the Project:** If you find OGCWin useful, consider starring ⭐ this repository and sharing it with others!

Happy gaming! 🎮🔥

---

## ⚠️ Liability & Disclaimer

**Use at your own risk.**

This utility makes significant changes to Windows system configurations, registry settings, and installed software to optimise performance and privacy. While every effort has been made to ensure safety and stability, modifying operating system settings always carries a risk.

* **Always backup your data** before running system utilities.
* **Create a Restore Point** (OGCWin can help with this) before applying major tweaks. The wizard will create a system restore point at the start.
* I am **not responsible** for any system instability, data loss, or issues that may arise from using this software.
* By using this tool, you acknowledge that you understand these risks.

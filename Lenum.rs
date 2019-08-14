#![allow(non_snake_case)]

extern crate colored;

use std::process::{Command, Stdio};
use colored::Colorize;
use std::env;
use std::path::Path;


fn main() {
    println!("###############################################");
    println!("#        Lenum - Linux Enumeration Tool       #");
    println!("# Tool was made by A.Tserpelis aka trickster0 #");
    println!("###############################################\r\n\r\n");
    linux();
}

fn look_path(path: &str) -> Result<bool, std::env::VarError> {
    std::env::var("PATH").and_then(|paths| {
        Ok(paths
            .split(":")
            .map(|p| format!("{}/{}", p, path))
            .any(|p| Path::new(&p).exists()))
        })
    }


fn linux() {
    let whoami = Command::new("whoami").output().expect("Command failed to be executed.");
    println!("[+]Current User: {}", String::from_utf8_lossy(&whoami.stdout));
    let hostname = Command::new("hostname").output().expect("Command failed to be executed.");
    println!("[+]Hostname: {}", String::from_utf8_lossy(&hostname.stdout));
    let time = Command::new("date").output().expect("Command failed to be executed.");
    println!("[+]Time: {}", String::from_utf8_lossy(&time.stdout));  
    let users = Command::new("w").output().expect("Command failed to be executed.");
    println!("[+]Logged In Users:{}\r\n", String::from_utf8_lossy(&users.stdout));
    let id = Command::new("id").output().expect("Command failed to be executed.");
    println!("[+]ID:\r\n{}", String::from_utf8_lossy(&id.stdout));
    let kernel = Command::new("uname").arg("-a").output().expect("Command failed to be executed.");
    println!("[+]Kernel Version:\r\n{}", String::from_utf8_lossy(&kernel.stdout));
    println!("[+]System Protections:");
    let mmap_min_addr = Command::new("cat").arg("/proc/sys/vm/mmap_min_addr").output().expect("Command failed to be executed.");
    if mmap_min_addr.stdout.contains(&b'0') {
        println!("mmap_min_addr:{}","Disabled".red());
    }
    else {
        println!("mmap_min_addr:{}","Enabled".green());
    }
    let sysinfo = Command::new("cat").arg("/etc/lsb-release").output().expect("Command failed to be executed.");
    let aslr = Command::new("cat").arg("/proc/sys/kernel/randomize_va_space").output().expect("Command failed to be executed.");
    if aslr.stdout.contains(&b'0') {
        println!("ASLR:{}","Disabled".red());
    }
    else {
        println!("ASLR:{}","Enabled".green());
    }   
    let aslr = Command::new("cat").arg("/proc/sys/kernel/kptr_restrict").output().expect("Command failed to be executed.");
    if aslr.stdout.contains(&b'0') {
        println!("kptr_restrict:{}","Disabled".red());
    }
    else {
        println!("kptr_restrict:{}","Enabled".green());
    }   
    let smep = Command::new("cat").arg("/proc/cpuinfo").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man11_vuln = Command::new("grep").arg("smep").stdin(smep.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    if man11_vuln.stdout.len()>4 {
        println!("SMEP:{}", "Enabled".green());
    }
    else {
        println!("SMEP:{}", "Disabled".red());
    }
    let smap = Command::new("cat").arg("/proc/cpuinfo").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man12_vuln = Command::new("grep").arg("smap").stdin(smap.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    if man12_vuln.stdout.len()>4 {
        println!("SMAP:{}", "Enabled".green());
    }
    else {
        println!("SMAP:{}", "Disabled".red());
    }
    let kaslr = Command::new("cat").arg("/proc/cmdline").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man13_vuln = Command::new("grep").arg("kaslr").stdin(kaslr.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    if man13_vuln.stdout.len()>3 {
        println!("KASLR:{}", "Enabled".green());
    }
    else {
        println!("KASLR:{}", "Disabled".red());
    }
    println!("\r\n[+]System Information:\r\n{}", String::from_utf8_lossy(&sysinfo.stdout));   
    let ifconfig = Command::new("ifconfig").output().expect("Command failed to be executed.");
    println!("[+]IP Information:\r\n{}", String::from_utf8_lossy(&ifconfig.stdout));
    match env::var("PATH"){
        Ok(pathway) => println!("[+]PATH Variable:\r\n{}",pathway),
        Err(_e) => println!("No PATH variable set."),
    };
    let env_env = Command::new("env").output().expect("Command failed to be executed.");
    println!("\r\n[+]Environmental Variables:\r\n{}", String::from_utf8_lossy(&env_env.stdout));
    let passwd = Command::new("cat").arg("/etc/passwd").output().expect("Command failed to be executed.");
    println!("[+]Passwd Information:\r\n{}", String::from_utf8_lossy(&passwd.stdout));
    let passwd = Command::new("ls").arg("-l").arg("/etc/passwd").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man1_vuln = Command::new("cut").arg("-d").arg(" ").arg("-f").arg("1").stdin(passwd.stdout.expect("Command failed to be executed.")).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man2_vuln = Command::new("cut").arg("-c").arg("9-").stdin(man1_vuln.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    println!("[+]Checking If Passwd is Writable(firefart):");
    if man2_vuln.stdout.contains(&b'w') {
        println!("{}", "Passwd is writable and vulnerable!".green());
    }
    else {
        println!("{}", "Passwd is not writable.".red());
    }
    let sudoer = Command::new("ls").arg("-l").arg("/etc/sudoers").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man3_vuln = Command::new("cut").arg("-d").arg(" ").arg("-f").arg("1").stdin(sudoer.stdout.expect("Command failed to be executed.")).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man4_vuln = Command::new("cut").arg("-c").arg("9-").stdin(man3_vuln.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    println!("\r\n[+]Checking If Sudoers is Writable():");
    if man4_vuln.stdout.contains(&b'w') {
        println!("{}", "Sudoers is writable and vulnerable!".green());
    }
    else {
        println!("{}", "Sudoers is not writable.".red());
    }
    let shadow = Command::new("ls").arg("-l").arg("/etc/shadow").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man5_vuln = Command::new("cut").arg("-d").arg(" ").arg("-f").arg("1").stdin(shadow.stdout.expect("Command failed to be executed.")).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man6_vuln = Command::new("cut").arg("-c").arg("9-").stdin(man5_vuln.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    println!("\r\n[+]Checking If Shadow is Writable:");
    if man6_vuln.stdout.contains(&b'w') {
        println!("{}", "Shadow is writable and vulnerable!".green());
    }
    else {
        println!("{}", "Shadow is not writable.".red());
    }
    let crontab = Command::new("cat").arg("/etc/crontab").output().expect("Command failed to be executed.");
    println!("\r\n[+]Checking for Cron tasks: {}", String::from_utf8_lossy(&crontab.stdout));
    let sudonv = Command::new("sudo").arg("-nv").output().expect("Command failed to be executed.");
    println!("[+]Check if current user is sudoer:");
    if sudonv.stderr.contains(&b':'){
        println!("{}","Sudoer".green());
    }
    else {
        println!("{}","Non-Sudoer".red())
    }
    let sudol = Command::new("sudo").arg("-ln").output().expect("Command failed to be executed.");
    println!("\r\n[+]Check what you can run as your current user. If nothing will be printed then you are Sudoer but you need the password:\r\n{}", String::from_utf8_lossy(&sudol.stdout));
    println!("[+]Checking for important programs:");
    for file in ["nmap","su", "sudo","perl","python","python3","python2.7","ruby","bash","sh","dash","nc","netcat","vim","vi","ssh","curl","wget","find","tar","scp","ftp","git","socat","telnet","tftp","sed","grep","gcc","make"].iter() {
        match look_path(file){
            Ok(found) => {
                if found {
                    println!("{}:{}",file,"Found".green())
                }
                else {
                    println!("{}:{}",file,"Not Found".red())
                }
            }
            Err(_e) => println!("Failed to look for programs.")
        }
    }
    let lastlogged = Command::new("lastlog").output().expect("Command failed to be executed.");
    println!("\r\n[+]List of last logins: {}", String::from_utf8_lossy(&lastlogged.stdout));
    let homeusers = Command::new("ls").arg("/home").output().expect("Command failed to be executed.");
    println!("[+]List of home users:\r\n{}", String::from_utf8_lossy(&homeusers.stdout));
    println!("[+]Trying to find wrong permissions on private SSH keys:");
    for userhome in String::from_utf8_lossy(&homeusers.stdout).lines(){
        let mut pathvar = String::from("/home/");
        pathvar.push_str(userhome);
        pathvar.push_str("/.ssh/id_rsa");
        let sshkeys = Command::new("cat").arg(pathvar).output().expect("Command failed to be executed.");
        if sshkeys.stdout.len() < 3 {
            println!("{}:{}",userhome, "You do not have permission.".red());
        }
        else {
            println!("{}:{}\r\n\r\n{}",userhome, "You have permission.".green(), String::from_utf8_lossy(&sshkeys.stdout));
        }
    }
    println!("\r\n[+]Checking If authorized_keys is Writable:");
    for userhome in String::from_utf8_lossy(&homeusers.stdout).lines(){
        let mut pathvar3 = String::from("/home/");
        pathvar3.push_str(userhome);
        pathvar3.push_str("/.ssh/authorized_keys");
        let shadow = Command::new("ls").arg("-l").arg(pathvar3).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
        let man9_vuln = Command::new("cut").arg("-d").arg(" ").arg("-f").arg("1").stdin(shadow.stdout.expect("Command failed to be executed.")).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
        let man10_vuln = Command::new("cut").arg("-c").arg("9-").stdin(man9_vuln.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
        if man10_vuln.stdout.contains(&b'w') {
            println!("{}:{}\r\n",userhome, "Authorized_keys is writable and vulnerable!".green());
        }
        else {
            println!("{}:{}\r\n", userhome, "Authorized_keys is not writable/doesn't exist or you do not have permissions.".red());
        }
    }
    println!("[+]Trying to find wrong permissions on user history.");
    for userhome in String::from_utf8_lossy(&homeusers.stdout).lines(){
        let mut pathvar2 = String::from("/home/");
        pathvar2.push_str(userhome);
        pathvar2.push_str("/.bash_history");
        let history = Command::new("cat").arg(pathvar2).output().expect("Command failed to be executed.");
        if history.stdout.len() < 3 {
            println!("{}:{}",userhome, "You do not have permission.".red());
        }
        else {
            println!("{}:{}",userhome, "You have permission.".green());
        }
    }
    println!("\r\n[+]Checking If /root is Readable:");
    let rootdir = Command::new("ls").arg("-l").arg("/root").stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man7_vuln = Command::new("cut").arg("-d").arg(" ").arg("-f").arg("1").stdin(rootdir.stdout.expect("Command failed to be executed.")).stdout(Stdio::piped()).spawn().expect("Command failed to be executed.");
    let man8_vuln = Command::new("cut").arg("-c").arg("8-").stdin(man7_vuln.stdout.expect("Command failed to be executed.")).output().expect("Command failed to be executed.");
    if man8_vuln.stdout.contains(&b'r') {
        println!("{}", "/root directory is readable.".green());
    }
    else {
        println!("{}", "/root directory is not readable.".red());
    }
    let tasks = Command::new("ps").arg("aux").output().expect("Command failed to be executed.");
    println!("\r\n[+]Running Processes:\r\n{}", String::from_utf8_lossy(&tasks.stdout));
    let netstat = Command::new("netstat").arg("-auntp").output().expect("Command failed to be executed.");
    println!("[+]Running Services:\r\n{}", String::from_utf8_lossy(&netstat.stdout));
    let suid = Command::new("find").arg("/").arg("-perm").arg("/6000").output().expect("Command failed to be executed.");
    println!("[+]SUID/SGID Binaries. This may take a while...:\r\n{}", String::from_utf8_lossy(&suid.stdout));
    let dns = Command::new("cat").arg("/etc/resolv.conf").output().expect("Command failed to be executed.");
    println!("[+]DNS Server:\r\n{}", String::from_utf8_lossy(&dns.stdout));   
    let route = Command::new("route").output().expect("Command failed to be executed.");
    println!("[+]Routes:\r\n{}", String::from_utf8_lossy(&route.stdout));   
    let arp = Command::new("arp").arg("-a").output().expect("Command failed to be executed.");
    println!("[+]ARP Table:\r\n{}", String::from_utf8_lossy(&arp.stdout));    
    let services = Command::new("ls").arg("-l").arg("/etc/init.d/").output().expect("Command failed to be executed.");
    println!("[+]Init Services:\r\n{}", String::from_utf8_lossy(&services.stdout)); 
    let sudoversion = Command::new("sudo").arg("-V").output().expect("Command failed to be executed.");
    println!("[+]Sudo Version:\r\n{}", String::from_utf8_lossy(&sudoversion.stdout)); 
    let htpasswd = Command::new("find").arg("/").arg("-name").arg(".htpasswd").output().expect("Command failed to be executed.");
    println!("[+]Looking for htpasswd files:\r\n{}", String::from_utf8_lossy(&htpasswd.stdout)); 
    let webserver = Command::new("ls").arg("/var/www/html").output().expect("Command failed to be executed.");
    println!("[+]Possible webserver files:\r\n{}", String::from_utf8_lossy(&webserver.stdout)); 
    let git = Command::new("find").arg("/").arg("-name").arg(".git-credentials").output().expect("Command failed to be executed.");
    println!("[+]Looking for git credentials:\r\n{}", String::from_utf8_lossy(&git.stdout)); 
    let docker = Command::new("find").arg("/").arg("-name").arg("Dockerfile").output().expect("Command failed to be executed.");
    println!("[+]Looking for Dockerfiles:\r\n{}", String::from_utf8_lossy(&docker.stdout)); 
    let fstab = Command::new("cat").arg("/etc/fstab").output().expect("Command failed to be executed.");
    println!("[+]Fstab Entries:\r\n{}", String::from_utf8_lossy(&fstab.stdout)); 
    let exports = Command::new("cat").arg("/etc/exports").output().expect("Command failed to be executed.");
    println!("[+]Possible Exports for NFS:\r\n{}", String::from_utf8_lossy(&exports.stdout)); 
    println!("[+]Bye, I hope you pwn!");
}

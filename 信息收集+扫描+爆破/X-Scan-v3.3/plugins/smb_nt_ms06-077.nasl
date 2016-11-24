#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23839);
 script_bugtraq_id(21495);
 script_xref(name:"OSVDB", value:"30817");
 script_cve_id("CVE-2006-5584");
  
 script_version("$Revision: 1.10 $");

 name["english"] = "MS06-077: Vulnerability in Remote Installation Service Could Allow Remote Code Execution (926121)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through TFTPF." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of TFTPD installed by the Remote
Installation Service which allows everyone to overwrite files on the
remote host. 

An attacker may exploit this flaw to replace SYSTEM files and execute
arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-077.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );



script_end_attributes();

 
 summary["english"] = "Determines the parameters of the remote TFTP server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) 
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
key = "SYSTEM\CurrentControlSet\Services\TFTPD";
item = "DisplayName";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (isnull(key_h))
{
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:item);

RegCloseKey(handle:key_h);

if (isnull(value))
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0); 
}

fixed = 0;

key = "SYSTEM\CurrentControlSet\Services\TFTPD\Parameters";
item = "Masters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull(value))
   fixed = 1;

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();

if (fixed == 0)
 {
 set_kb_item(name:"SMB/Missing/MS06-077", value:TRUE);
 hotfix_security_hole();
 }

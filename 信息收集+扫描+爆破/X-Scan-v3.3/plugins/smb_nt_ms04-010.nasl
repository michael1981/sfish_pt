#
# Copyright (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12091);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2004-0122");
 script_bugtraq_id(9828);
 script_xref(name:"OSVDB", value:"4169");

 name["english"] = "MS04-010: MSN Messenger Information Disclosure (838512)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to read files on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger. 

The remote host appears to be vulnerable to a remote attack wherein an
attacker can read any local file that the victim has 'read' access to." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Messenger 6.0 and 6.1 :

http://www.microsoft.com/technet/security/bulletin/ms04-010.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();


 summary["english"] = "Checks for MS04-010";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_nt_ms05-009.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


if ( get_kb_item("SMB/890261") ) exit(0);
  exit (0);


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:5,xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);
if ( hotfix_missing(name:"911565") <= 0 )


name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}

key = "SOFTWARE\Microsoft\MSNMessenger";
item = "InstallationDirectory";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  key = "SOFTWARE\Classes\Installer\Products\C838BEBA7A1AD5C47B1EB83441062011";
  item = "Version";
  
  key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h2, item:item);
   if (!isnull (value))
   {
    set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version", value:value[1]);
    a = ((value[1]) & 0xFF000000) >> 24;
    b = ((value[1] & 0xFF0000)) >> 16;
    c = value[1] & 0xFFFF;

    if ( ( a == 6 ) &&
	 ( (b == 0) || ( (b == 1) && (c < 211) ) ) )
 {
 set_kb_item(name:"SMB/Missing/MS04-010", value:TRUE);
 hotfix_security_note();
 }
   }
  
   RegCloseKey(handle:key_h2);
  }
 }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();

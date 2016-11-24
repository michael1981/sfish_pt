#
# (C) Tenable Network Security, Inc.
#
 

include("compat.inc");

if(description)
{
 script_id(10430);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0589");
 name["english"] = "SMB Registry : permissions of keys that can lead to admin";
 
 script_set_attribute(attribute:"synopsis", value:
"Local users can gain administrator privileges." );
 script_set_attribute(attribute:"description", value:
"The following keys contain the name of the program that shall be started
when the computer starts. The users who have the right to modify them can
easily  make the admin run a trojan program which will give them admin 
privileges." );
 script_set_attribute(attribute:"solution", value:
"Use regedt32 and set the permissions of this key to :

- Admin group  : Full Control
- System       : Full Control
- Everyone     : Read

Make sure that 'Power Users' do not have any special privilege for this key." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );


 script_name(english:name["english"]);

script_end_attributes();

 
 summary["english"] = "Determines the access rights of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

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

keys[0] = "Software\Microsoft\Windows\CurrentVersion\Run";
keys[1] = "Software\Microsoft\Windows\CurrentVersion\RunOnce";
keys[2] = "Software\Microsoft\Windows\CurrentVersion\RunOnceEx";
keys[3] = "Software\Microsoft\Windows NT\CurrentVersion\AeDebug";
keys[4] = "Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

vuln = 0;
vuln_keys = "";

for(my_counter=0;keys[my_counter];my_counter=my_counter+1)
{
 key_h = RegOpenKey(handle:hklm, key:keys[my_counter], mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
 
 if(!isnull(key_h))
 {
  rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
  if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
  {
   vuln_keys += '\nHKLM\\' + keys[my_counter];
   vuln = vuln + 1;
  }
  RegCloseKey (handle:key_h);
 }
}

RegCloseKey (handle:hklm);
NetUseDel();

if(vuln)
{
 report = 
"The following registry keys are writeable by users who are not in 
the admin group : 
" 
+
 vuln_keys ;

 security_hole(port:port, extra:report);
}


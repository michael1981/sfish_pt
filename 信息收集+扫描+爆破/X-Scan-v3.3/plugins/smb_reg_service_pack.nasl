#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10401);
 script_version ("$Revision: 1.37 $");
 script_cve_id("CVE-1999-0662");
 name["english"] = "SMB Registry : NT4 Service Pack version";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote system is up to date." );
 script_set_attribute(attribute:"description", value:
"By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion
it was possible to determine that the remote Windows NT 4 system has the latest service pack
installed." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 if ( defined_func("bn_random") ) script_dependencie("ssh_get_info.nasl");
 
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

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

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "CurrentVersion";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item2 = "CSDVersion";
 value2 = RegQueryValue(handle:key_h, item:item2);
 if (!isnull(value2) && "EMC Celerra File Server" >< value2[1])
 {
  RegCloseKey(handle:key_h);
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
 }

 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value) && value[1] )
    set_kb_item(name:"SMB/WindowsVersion", value:value[1]);

 if (!isnull (value2) )
 {
  if ( value2[1] ) set_kb_item(name:"SMB/CSDVersion", value:value2[1]);
  if(value[1] == "4.0")
  {
    if ( value2[1] ) set_kb_item(name:"SMB/WinNT4/ServicePack", value:value2[1]);
   if(ereg(string:value2[1], pattern:"^Service Pack 6.*$"))
   {
    report = string ("\n", "The remote WindowsNT is running ", value2[1], ".");

    security_note(extra:report, port:port);
   }
  }
  else if ( (value[1] == "5.0") && (value2[1] == "Service Pack 4"))
  {
   key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\Update Rollup 1";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( ! isnull(key_h2) )
   {
    set_kb_item(name:"SMB/URP1", value:TRUE);
    RegCloseKey(handle:key_h2);  
   }
   else
   {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Update Rollup 1";
    key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key_h2) )
    {
     set_kb_item(name:"SMB/URP1", value:TRUE);
     RegCloseKey(handle:key_h2);  
    }
   }
  }

  RegCloseKey(handle:key_h);
 }
}

RegCloseKey(handle:hklm);
NetUseDel();

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12111);
 script_version("$Revision: 1.4 $");

 script_name(english:"PhatBOT detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a trojan installed." );

 script_set_attribute(attribute:"description", value:
"The remote systems appears to have PhatBOT installed.  
This program allows the machine to be controlled via a P2P 
network.  PhatBOT is extremely sophisticated and allows the 
remote attacker to use the victim machine to perform various
actions." );

 script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/research/threats/phatbot" );
 script_set_attribute(attribute:"solution", value:
"Remove PhatBOT immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks if PhatBOT is installed.");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start script
include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) 
  exit(1,"KB 'SMB/Registry/Enumerated' not set.");

path[0] = "Software\Microsoft\Windows\CurrentVersion\Run\Generic Service Process";
path[1] = "Software\Microsoft\Windows\CurrentVersion\RunServices\Generic Service Process";

port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(1,"Could not get port state '"+ port + "' port.");

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
          
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(1, "Could not connect to HKLM Registry hive.");
}

for (i=0; path[i]; i++) 
{
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) ) 
       { 
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_hole(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}

RegCloseKey(handle:handle);
NetUseDel();

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11458);
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"SMB Registry : No dial in");
 script_summary(english:"Determines the value of a remote key");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Dial-in access is enabled."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "Dial-in access is enabled on the remote Windows host.  Provided a\n",
   "modem is installed, attackers may be able to dial into this host,\n",
   "bypassing firewall restrictions, and gaining access to the internal\n",
   "network."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Edit the registry and set the value of the registry key\n",
   "'HKLM\\Software\\Microsoft\\Windows\\Policies\\Network\\nodialin' to 1."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/03/24"
 );
 script_end_attributes();

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


key = "Software\Microsoft\Windows\Policies\Network";
item = "NoDialIn";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (!isnull (value) && (value[1] == 0))
   security_warning(port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();


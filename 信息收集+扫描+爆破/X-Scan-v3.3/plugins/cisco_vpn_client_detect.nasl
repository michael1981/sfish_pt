#
# Script Written By Ferdy Riphagen 
# Script distributed under the GNU GPLv2 License. 
#
# Tenable grants a special exception for this plugin to use the library 
# 'smb_func.inc'. This exception does not apply to any modified version of 
# this plugin.
#


include("compat.inc");

if (description) {
 script_id(25549);
 script_version("$Revision: 1.7 $");

 script_set_attribute(attribute:"synopsis", value:
"There is a VPN client installed on the remote Windows host." );
 script_set_attribute(attribute:"description", value:
"The Cisco VPN Client is installed on the remote Windows host.  This
software can be used for secure connectivity." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/sw/secursw/ps2308/index.html" );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

script_end_attributes();


 script_name(english:"Cisco VPN Client Version Detection");
 summary = "Detects the version number of the Cisco VPN Client in use";
 script_summary(english:summary);
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2007-2009 Ferdy Riphagen");

 script_require_ports(139, 445);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport");
 exit(0);
}

include("smb_func.inc");
include("misc_func.inc");

login = kb_smb_login();
pass = kb_smb_password();
port = kb_smb_transport();
name = kb_smb_name();
domain = kb_smb_domain();

if(!get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if(!soc || (!name)) exit(0);

function cleanup(opt) {
	
	if (opt == 1) exit(0);
	else if (opt == 2) {
		NetUseDel();
		exit(0);
	}
}

# modified 'get_dword' to get the bytes in the right format.
function get_dword2(blob, pos) {
 	global_var blob, pos;

 	if (pos > (strlen(blob) - 4)) return NULL;
	return (ord(blob[pos]) << 16) +
 			(ord(blob[pos+1]) << 24) +
			(ord(blob[pos+2])) +
 			(ord(blob[pos+3]) << 8);
}

session_init(socket:soc, hostname:name);
ipc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$"); 
if (ipc != 1) cleanup(opt:2);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) cleanup(opt:2);

key = "SOFTWARE\Cisco Systems\VPN Client";
regopen = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(regopen)) {
 	value = RegQueryValue(handle:regopen, item:"InstallPath");
	RegCloseKey(handle:regopen);
	RegCloseKey(handle:hklm);
	if(!isnull(value)) path = value[1]; 
	else cleanup(opt:2);
}
else cleanup(opt:2);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1vpngui.exe", string:path);

conn = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (conn != 1) cleanup(opt:1);

fopen = CreateFile(
	file:exe,
    desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING
);

if (isnull(fopen)) cleanup(opt:2);
ret = GetFileVersionEx(handle:fopen);
CloseFile(handle:fopen);

if (!isnull(ret)) children = ret['Children'];
if (!isnull(children)) info = children['VarFileInfo'];
if (isnull(info)) cleanup(opt:2);

trans = toupper(hexstr(dec2hex(
			num:get_dword2(
			blob:info['Translation'], pos:0))));
if (isnull(trans)) cleanup(opt:2);

fileinfo = children['StringFileInfo'];
if (!isnull(fileinfo)) data = fileinfo[trans];
if (!isnull(data)) ver = data['ProductVersion'];

if (!isnull(ver)) {
	set_kb_item(name:"SMB/CiscoVPNClient/Version", value:ver);
	report = string(
		"\n",
		"Plugin output :\n\n",
		"Version ", ver, " of the Cisco VPN Client is installed.\n"
		);
	security_note(port:port, extra:report);
}
cleanup(opt:2);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34401);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4020");
 script_bugtraq_id(31693);
 script_xref(name:"OSVDB", value:"49052");

 name["english"] = "MS08-056: Microsoft Office CDO Protocol (cdo:) Content-Disposition: Attachment Header XSS (957699)";


 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote installation of Microsoft Office is vulnerable to an information disclosure
flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office
which is subject to an information disclosure flaw.

When a user clicks on a special CDO URL, an attacker could
inject a client side script which may be used to disclose
information.

To succeed, the attacker would have to send a rogue CDO URL
to a user of the remote computer and have it click it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP :

http://www.microsoft.com/technet/security/bulletin/ms08-056.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Determines if a given registry entry is present";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

office_version = hotfix_check_office_version ();
if ( !office_version || "10.0" >!< office_version ) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);



session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}

key = "SOFTWARE\Classes\PROTOCOLS\Handler\cdo";
item = "CLSID";
value = NULL;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:item);
  RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();

if ( ! isnull(value) ) {
 set_kb_item(name:"SMB/Missing/MS08-056", value:TRUE);
 hotfix_security_note();
 }




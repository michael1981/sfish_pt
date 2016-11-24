#
# (C) Tenable Network Security, Inc.
#

#Ref: 
# From: "morning_wood" <se_cur_ity@hotmail.com>
# To: <bugtraq@securityfocus.com>
# Subject: IRCXpro 1.0 - Clear local and default remote admin passwords
# Date: Tue, 3 Jun 2003 00:57:45 -0700


include("compat.inc");

if(description)
{
 script_id(11696);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(7792);
 script_xref(name:"OSVDB", value:"4660"); 
 
 script_name(english:"IRCXPro Clear Text Passwords Local Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running IRCXPro.

This software stores the list of user names and passwords 
in clear text in \Program Files\IRCXPro\Settings.ini

An attacker with a full access to this host may use this flaw
to gain the list of passwords of your users." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Jun/45" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IRCXPro 1.1 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks settings.init");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(139, 445);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");


rootfile = hotfix_get_programfilesdir();
if(!rootfile) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
db =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\IRCXPro\settings.ini", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:db, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 CloseFile(handle:handle);
 security_note(port);
}

NetUseDel();

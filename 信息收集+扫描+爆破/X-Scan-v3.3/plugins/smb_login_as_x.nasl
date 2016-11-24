#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14818);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2004-0200");
 script_bugtraq_id(11173);
 script_xref(name:"IAVA", value:"2004-t-0028");

 name["english"] = "Possible GDI+ compromise";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host." );
 script_set_attribute(attribute:"description", value:
"It was possible to log into the remote host with the login 'X' and a
blank password. 

A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS04-028 creates such an account.  This
probably means that the remote host has been compromised by the use of
this exploit." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0152.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/Bulletin/MS04-028.mspx" );
 script_set_attribute(attribute:"solution", value:
"Re-install this host, as it has probably been compromised" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Logs in as user 'X' with no password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_login.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("global_settings.inc");

if ( supplied_logins_only ) exit(0);

login = "X";
pass  = "";

if(get_kb_item("SMB/any_login"))exit(0);


port = kb_smb_transport(); 
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login + string(rand()), password:pass + string(rand()), domain:NULL, share:"IPC$");
NetUseDel();
if ( r == 1 )  exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
if ( r == 1 ) security_hole(port);
NetUseDel();

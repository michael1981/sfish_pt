#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11561);
 script_cve_id("CVE-2003-1122");
 script_bugtraq_id(7476);
 script_xref(name: "CERT", value: "813737");
 script_xref(name:"OSVDB", value:"15656");
 script_version ("$Revision: 1.10 $");
 name["english"] = "ScriptLogic logging share";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be accessed on the emote server." );
 script_set_attribute(attribute:"description", value:
"The remote host has an accessible LOGS$ share. 

ScriptLogic creates this share to store the logs, but does
not properly set the permissions on it. As a result, anyone can
use it to read or modify, or possibily execute code." );
 script_set_attribute(attribute:"solution", value:
"Limit access to this share to the backup account and domain 
administrator." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "Connects to LOG$");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2008 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");


port = kb_smb_transport();
name = kb_smb_name();
if(!name)exit(0);


login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();



if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:dom, share:"LOGS$");
if ( r != 1 ) exit(1);

handle = FindFirstFile (pattern:"\*");
if ( ! isnull(handle) ) security_note(port);
NetUseDel();

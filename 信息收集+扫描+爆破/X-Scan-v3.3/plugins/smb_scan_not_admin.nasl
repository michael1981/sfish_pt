#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24786);
 script_version ("$Revision: 1.7 $");
 script_name(english:"Nessus Windows Scan Not Performed with Admin Privileges");
 
 script_set_attribute(attribute:"synopsis", value:
"The Nessus scan of this host may be incomplete due to insufficient
privileges provided." );
 script_set_attribute(attribute:"description", value:
"The Nessus scanner testing the remote host has been given SMB 
credentials to log into the remote host, however these credentials 
do not have administrative privileges.

Typically, when Nessus performs a patch audit, it logs into the 
remote host and reads the version of the DLLs on the remote host 
to determine if a given patch has been applied or not. This is 
the method Microsoft recommends to determine if a patch has been 
applied.

If your Nessus scanner does not have administrative privileges when 
doing a scan, then Nessus has to fall back to perform a patch audit 
through the registry which may lead to false positives (especially 
when using third party patch auditing tools) or to false negatives 
(not all patches can be detected thru the registry)." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure your scanner to use credentials with administrative 
privileges." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();
 
 script_summary(english:"Connects to ADMIN$");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

#

include ("smb_func.inc");

port = kb_smb_transport();
if(!port) port = 139;

name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login(); if ( ! login ) exit(0);
password = kb_smb_password();
domain   = kb_smb_domain();


if(!get_port_state(port))exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:password, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:password, domain:domain, share:"ADMIN$");
if ( r != 1 ) 
{
     security_note(port:0, extra:'It was not possible to connect to \\\\' + name + '\\ADMIN$');
}

NetUseDel ();

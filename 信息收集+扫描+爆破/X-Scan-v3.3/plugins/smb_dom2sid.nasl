#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10398);
 script_version ("$Revision: 1.39 $");
 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_xref(name:"OSVDB", value:"715");
 
 script_name(english:"SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration");
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the domain SID." );
 script_set_attribute(attribute:"description", value:
"By emulating the call to LsaQueryInformationPolicy() it was
possible to obtain the domain SID (Security Identifier).

The domain SID can then be used to get the list of users
of the domain" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english:"Gets the domain SID");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_scope.nasl", "netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/test_domain");
 script_require_ports(139, 445);
 exit(0);
}


d = get_kb_item("SMB/test_domain");
if(!d)exit(0);

include("smb_func.inc");

port = kb_smb_transport();
if(!port)port = 139;

if(!get_port_state(port))exit(0);

name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();
	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit (0);
}

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyPrimaryDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 exit (0);
}

sid = ret[1];

LsaClose (handle:handle);
NetUseDel ();


if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/domain_sid", value:hexstr(sid));

 report = string (
		"The remote domain SID value is :\n",
		sid2string(sid:sid));

 security_note(extra:report, port:port);
}

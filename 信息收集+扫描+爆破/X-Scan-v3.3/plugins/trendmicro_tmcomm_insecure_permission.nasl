#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24682);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-0856");
  script_bugtraq_id(22448);
  script_xref(name:"CERT", value:"666800");
  script_xref(name:"OSVDB", value:"33039");

  script_name(english:"Trend Micro Tmcomm.sys insecure permission");
  script_summary(english:"Checks if vulnerable version of tmcomm.sys is installed"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a local privilege escalation
issue." );
 script_set_attribute(attribute:"description", value:
"The version of tmcomm.sys installed on the remote system is prone to a
local privilege escalation vulnerability.  The issue exists due to
insecure permissions on Tmcomm.sys which allows write access to
'everyone' group on the remote system.  Successful exploitation of
this issue could lead to arbitrary code execution with SYSTEM
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cd52053" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/282240" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79809de0" );
 script_set_attribute(attribute:"solution", value:"Update the Anti-Rootkit Common Module (RCM) to version 1.600-1052.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
winroot = hotfix_get_systemroot();
if(isnull(winroot)) exit(0);

share  = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
windir = ereg_replace(pattern:"^[A-Za-z]:(.*)$", replace:"\1", string:winroot);

# Connect to the appropriate share.

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

file = windir + '\\system32\\drivers\\tmcomm.sys';

fh = CreateFile(file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

v = NULL;
if (!isnull(fh))
{
  v = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

if ( !isnull(v) && 
    ( (v[0] == 1 && v[1] < 6) ||
    (v[0] == 1 && v[1] == 6 && v[2] == 0 && v[3] < 1052) ))
  {
 info = string (
		'Version ', v[0], ".", v[1], ".", v[2], ".", v[3],  ' of tmcomm.sys is installed on the remote\n',
		'host under the following path :\n',
		'\n',
		'  ', winroot + '\\system32\\drivers\\tmcomm.sys'
		);

 report = string(
		"\n",
		info,"\n"
  		);
 security_hole(port:port, extra:report);
}

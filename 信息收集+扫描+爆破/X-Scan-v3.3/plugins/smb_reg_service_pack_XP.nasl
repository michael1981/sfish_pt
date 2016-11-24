#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# See the Nessus Scripts License for details
#
# Changes by Tenable
# - Updated to use compat.inc, updated security_note to use 'extra' arg (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(11119);
 script_bugtraq_id(10897, 11202);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0662");
 
 name["english"] = "SMB Registry : XP Service Pack version";
 
 script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote system has the latest service pack installed." );
 script_set_attribute(attribute:"description", value:
"By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion
it was possible to determine the Service Pack version of the Windows XP
system." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 
script_end_attributes();

 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Alert4Web.com");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/RegOverSSH") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.1")
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);

  report = string ("\n",
		"The remote Windows XP system has ", sp , " applied.\n");

  security_note(extra:report, port:port);
}

#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(17662);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0662", "CVE-2007-1537");
 script_bugtraq_id(12969, 12972, 13008, 23025);
 script_xref(name:"OSVDB", value:"33628");
 
 name["english"] = "SMB Registry : Windows 2003 Server Service Pack Detection";
 
 script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on 
the remote system." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the Service Pack version of the Windows
2003 system.  by reading the registry key
'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion'." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 
script_end_attributes();

 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.2" )
{
 if ( ereg(pattern:"Service Pack [1-9]", string:sp) )
 {
  set_kb_item(name:"SMB/Win2003/ServicePack", value:sp);
  report = string ("\n",
		"The remote Windows 2003 system has ",sp," applied",
                "\n");
  security_note(extra:report, port:port);
  exit(0);
 }
}


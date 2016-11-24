#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10531);
 script_bugtraq_id(7930, 8090, 8128, 8154);
 script_version ("$Revision: 1.40 $");
 script_cve_id("CVE-1999-0662", "CVE-2003-0350", "CVE-2003-0507");
 name["english"] = "SMB Registry : Win2k Service Pack version";
 
 script_name(english:name["english"]);
 

 script_set_attribute(attribute:"synopsis", value:
"The remote system has the latest service pack installed." );
 script_set_attribute(attribute:"description", value:
"By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\CSDVersion it was possible to determine the
Service Pack version of the remote Windows 2000 system." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion","SMB/CSDVersion");
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.0")
{
 if (sp)
 {
  if ( ("Service Pack 4" >< sp) && (get_kb_item("SMB/URP1")) )
  {
    replace_kb_item (name:"SMB/CSDVersion", value:"Service Pack 5");
    set_kb_item(name:"SMB/Win2K/ServicePack", value:"Service Pack 5");
  }
  else
    set_kb_item(name:"SMB/Win2K/ServicePack", value:sp);
 }


 if(sp && (ereg(pattern:"Service Pack [45]",string:sp)))
 {
  report = string ("The remote Windows 2000 system has ", sp , " applied.\n");

  security_note (port:port, extra:report);
 }
}

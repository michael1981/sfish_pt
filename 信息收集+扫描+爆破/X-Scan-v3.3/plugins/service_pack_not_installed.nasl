#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(26921);
 script_bugtraq_id(10897, 11202, 7930, 8090, 8128, 8154, 12969, 12972, 13008, 23025);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-0662", "CVE-2003-0350", "CVE-2003-0507", "CVE-2007-1537");
 
 name["english"] = "OS service pack not up to date";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote system is not up to date." );
 script_set_attribute(attribute:"description", value:
"The remote system has no service pack or the installed one is no
longer supported." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifesupsps" );
 script_set_attribute(attribute:"solution", value:
"Install the latest service pack." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";

 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl", "smb_reg_service_pack_W2K.nasl",
		"smb_reg_service_pack_XP.nasl", "smb_reg_service_pack_W2003.nasl");
 script_require_keys("SMB/WindowsVersion");
 exit(0);
}

# First checks Windows

v = get_kb_item("SMB/CSDVersion");
if ( v && "EMC Celerra File Server" >< v ) exit(0);


win_sp["4.0"] = "6a";
win_sp["5.0"] = "4";
win_sp["5.1"] = "3";
win_sp["5.2"] = "2";
win_sp["6.0"] = "2";

win_min_sp["4.0"] = "6a";
win_min_sp["5.0"] = "4";
win_min_sp["5.1"] = "2";
win_min_sp["5.2"] = "2";
win_min_sp["6.0"] = "0";

report = NULL;

win = get_kb_item("SMB/WindowsVersion"); 
if (win)
{
 port = get_kb_item("SMB/transport");
 if(!port)port = 445;

 sp = get_kb_item("SMB/CSDVersion");

 if (!sp)
   sp = "Service Pack 0";

 vers = ereg_replace(pattern:"Service Pack (.*)$", string:sp, replace:"\1");
 if (int(vers) < int(win_min_sp[win]))
   report = sp;

 if (report)
 {
  report = string ("\n",
		"The remote Windows ", win, " system has ", report , " applied.\n",
		"The system should have Service Pack ", win_sp[win], " installed.");

  security_hole(extra:report, port:port);
 }
}

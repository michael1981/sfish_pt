#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(18679);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2005-0564");
 script_bugtraq_id(14216);
 script_xref(name:"IAVA", value:"2005-B-0010");
 script_xref(name:"OSVDB", value:"17829");

 name["english"] = "MS05-035: Vulnerability in Word May Lead to Code Execution (903672)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Word." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue word file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms05-035.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
port = get_kb_item("SMB/transport");


v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.6764.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6764 ) {
 set_kb_item(name:"SMB/Missing/MS05-035", value:TRUE);
 hotfix_security_hole();
 }
  else
    set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672", value:TRUE);
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.8930
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8930) {
 set_kb_item(name:"SMB/Missing/MS05-035", value:TRUE);
 hotfix_security_hole();
 }
 else
    set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672", value:TRUE);
}

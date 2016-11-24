#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(18026);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-0963", "CVE-2005-0558");
 script_bugtraq_id(13122, 13119);
 script_xref(name:"IAVA", value:"2005-B-0010");
 script_xref(name:"OSVDB", value:"10549");
 script_xref(name:"OSVDB", value:"15470");

 name["english"] = "MS05-023: Vulnerability in Word May Lead to Code Execution (890169)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Word." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that may allow
arbitrary code to be run. 

To succeed, the attacker would have to send a rogue word file to a
user of the remote computer and have it open it.  Then the macros
contained in the word file would bypass the security model of word,
and would be executed." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000, 2002 and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-023.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl", "smb_nt_ms05-035.nasl");
 script_require_keys("SMB/Office/Word/Version");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
port = get_kb_item("SMB/transport");

if (get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672"))
  exit (0);

v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^11\..*", string:v))
  {
  # Word 2003 - updated in 11.0.6425.0
  middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6425) {
 set_kb_item(name:"SMB/Missing/MS05-023", value:TRUE);
 hotfix_security_hole();
 }
  }
else if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.6754.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6754 ) {
 set_kb_item(name:"SMB/Missing/MS05-023", value:TRUE);
 hotfix_security_hole();
 }
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.8929
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8929) {
 set_kb_item(name:"SMB/Missing/MS05-023", value:TRUE);
 hotfix_security_hole();
 }
}

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11885);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0659");
 script_bugtraq_id(8827);
 script_xref(name:"OSVDB", value:"10937");
 script_xref(name:"OSVDB", value:"10938");
 
 name["english"] = "MS03-045: Buffer Overrun in the ListBox and in the ComboBox (824141)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists because the ListBox control and the ComboBox
control both call a function, located in the User32.dll file, that
contains a buffer overrun.  A local interactive attacker could run a
program that sends a specially crafted Windows message to any
application that has implemented the ListBox control or the ComboBox
control, causing the application to take any action he specified. 

An attacker must have valid logon credentials to exploit the
vulnerability.  It can not be exploited remotely." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-045.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q824141";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.73", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1255", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"User32.dll", version:"5.1.2600.118", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.6799", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.7229", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.33550", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-045", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else
{
 if ( hotfix_check_sp(xp:2, nt:7) > 0 )
 {
  if ( hotfix_missing(name:"840987") == 0 ) exit(0);
  if ( hotfix_missing(name:"896424") == 0 ) exit(0);
  if ( hotfix_missing(name:"925902") == 0 ) exit(0);
 }

 if ( hotfix_check_sp(win2k:5) > 0 )
 {
  if ( hotfix_missing(name:"840987") == 0 ) exit(0);
  if ( hotfix_missing(name:"841533") == 0 ) exit(0);
  if ( hotfix_missing(name:"890859") == 0 ) exit(0);
 }

 if (hotfix_missing(name:"891711") == 0) exit (0);

 if ( hotfix_missing(name:"824141") > 0 )
 	 {
 set_kb_item(name:"SMB/Missing/MS03-045", value:TRUE);
 hotfix_security_hole();
 }
}

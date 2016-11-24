#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25487);
 script_version("$Revision: 1.10 $");

 script_cve_id(
  "CVE-2006-2111", 
  "CVE-2007-1658", 
  "CVE-2007-2225", 
  "CVE-2007-2227"
 );
 script_bugtraq_id(17717, 23103, 24392, 24410);
 script_xref(name:"OSVDB", value:"25073");
 script_xref(name:"OSVDB", value:"34102");
 script_xref(name:"OSVDB", value:"35345");
 script_xref(name:"OSVDB", value:"35346");

 name["english"] = "MS07-034: Cumulative Security Update for Outlook Express and Windows Mail (929123)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express with
several security flaws that may allow an attacker to execute arbitrary
code on the remote host. 

To exploit this flaw, an attacker would need to send a malformed email
to a victim on the remote host and have him open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and
Windows Mail :

See: http://www.microsoft.com/technet/security/bulletin/ms07-034.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 929123";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:3, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.16480", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4073", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.2929", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3138", dir:"\system32")  )
 {
 set_kb_item(name:"SMB/Missing/MS07-034", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

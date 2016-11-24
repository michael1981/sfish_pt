#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26962);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-3897");
 script_bugtraq_id(25908);
 script_xref(name:"OSVDB", value:"37631");

 name["english"] = "MS07-056: Cumulative Security Update for Outlook Express and Windows Mail (941202)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express
which contains several security flaws which may allow an attacker to
execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send a malformed email
to a victim on the remote host and have him open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and
Windows Mail :

http://www.microsoft.com/technet/security/bulletin/ms07-056.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 941202";

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



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2k:6, win2003:3, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.16545", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4133", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.2992", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3198", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Inetcomm.dll", version:"6.0.2800.1914", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",	    file:"Inetcomm.dll", version:"5.50.4980.1600", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-056", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

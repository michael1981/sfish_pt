#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33877);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-1448");
 script_bugtraq_id(30585);
 script_xref(name:"OSVDB", value:"47413");

 name["english"] = "MS08-048: Security Update for Outlook Express and Windows Mail (951066)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"An information disclosure vulnerability is present on the remote host
due to an issue in Outlook Express / Microsoft Mail" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express
which contains a flaw which might be used to cause an information
disclosure. 

To exploit this flaw, an attacker would need to send a malformed email
to a victim on the remote host and have him open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and
Windows Mail :

http://www.microsoft.com/technet/security/bulletin/ms08-048.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 951066";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:4, win2k:6, win2003:3, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.16669", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.20810", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.18049", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.22154", min_version:"6.0.6001.22000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4325", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.3168", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3350", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Inetcomm.dll", version:"6.0.2900.5579", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Inetcomm.dll", version:"6.0.2800.1933", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",	    file:"Inetcomm.dll", version:"5.50.4990.2500", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-048", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

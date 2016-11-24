#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11144);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2002-0699");
 script_bugtraq_id(5593);
 script_xref(name:"OSVDB", value:"864");

 script_name(english:"MS02-048: Flaw in Certificate Enrollment Control Could Allow Deletion of Digital Certificates (323172)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to delete digital certificates on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Certificate Enrollment
control that may allow an attacker to delete certificates. 

To exploit this vulnerability an attacker must create a rogue web
server with SSL and lure the user to visit this site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-048.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q323172, Certificate Enrollment Flaw");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-048", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q323172") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-048", value:TRUE);
 hotfix_security_warning();
 }

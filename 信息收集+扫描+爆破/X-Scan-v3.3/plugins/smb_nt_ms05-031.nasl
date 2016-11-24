#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18492);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2005-1212");
 script_bugtraq_id(13944);
 script_xref(name:"OSVDB", value:"17304");

 name["english"] = "MS05-031: Vulnerability in Step-by-Step Interactive Training (898458)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the training
software." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Step-by-Step
Interactive Training that contains a flaw which may lead to remote
code execution. 

To exploit this flaw, an attacker would need to trick a user on the
remote host into opening a malformed file with the affected
application." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch :

http://www.microsoft.com/technet/security/bulletin/ms05-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of MRUN32.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

if ( hotfix_check_fversion(file:"mrun32.exe", version:"3.4.1.101") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-031", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();

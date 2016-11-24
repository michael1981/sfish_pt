#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(33107);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2007-0216","CVE-2008-0105","CVE-2008-0108");
 script_bugtraq_id(27657,27658,27659);

 name["english"] = "MS08-011: Vulnerabilities in Microsoft Works File Converter Could Allow Remote Code Execution (947081)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office Works Converter
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the wps header handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, Works 8.0 and Works 2005:

http://www.microsoft.com/technet/security/bulletin/ms08-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of Works Converter";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = kb_smb_transport();
if (!is_accessible_share()) exit(0);  

commonfiles = hotfix_get_officecommonfilesdir();
if  ( ! commonfiles ) exit(0);

if (hotfix_check_fversion(file:"works632.cnv", path:commonfiles +"\Microsoft Shared\TextConv", version:"7.3.1005.0", min_version:"7.0.0.0") == HCF_OLDER)
 {
 set_kb_item(name:"SMB/Missing/MS08-011", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();

#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31792);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-1089", "CVE-2008-1090");
 script_bugtraq_id(28555, 28556);
 script_xref(name:"OSVDB", value:"44169");
 script_xref(name:"OSVDB", value:"44170");

 name["english"] = "MS08-019: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (949032)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visio." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio which has a vulnerability
in the way it handles object headers and validates memory which could be used
by an attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a specially
crafted visio document to a user on the remote host and lure him into opening 
it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2002, 2003 and 2007 :

http://www.microsoft.com/technet/security/Bulletin/MS08-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 949032";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


vers = get_kb_item("SMB/Office/Visio");
if ("12.0" >!< vers && "11.0" >!< vers && "10.0" >!< vers)
  exit(0);

path = get_kb_item("SMB/Office/VisioPath");
if (isnull(path))
  exit(0);

if (is_accessible_share())
{
 e = 0;

 if ( "12.0" >< vers )  # Visio 2007
 {
  if ( hotfix_check_fversion(path:path, file:"Vislib.dll", version:"12.0.6300.5000") == HCF_OLDER ) e ++;
 }
 else if ( "11.0" >< vers )  # Visio 2003
 {
  if ( hotfix_check_fversion(path:path, file:"Visio11\Vislib.dll", version:"11.0.8207.0") == HCF_OLDER ) e ++;
 }
 else if ( "10.0" >< vers )  # Visio 2002
 {
  if ( hotfix_check_fversion(path:path, file:"Visio10\Vislib.dll", version:"10.0.6871.4") == HCF_OLDER ) e ++;
 }


 if ( e ) {
 set_kb_item(name:"SMB/Missing/MS08-019", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
 exit (0);
}

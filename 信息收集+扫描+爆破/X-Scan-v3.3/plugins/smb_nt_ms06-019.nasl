#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(21332);
 script_bugtraq_id (17908);
 script_cve_id("CVE-2006-0027");
 script_xref(name:"OSVDB", value:"25338");
 script_version("$Revision: 1.10 $");

 name["english"] = "MS06-019: Vulnerability in Microsoft Exchange Could Allow Remote Code Execution (916803)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of exchange which is vulnerable
to a bug in the vCal or iCal attachment handling routine which may 
allow an attacker execute arbitrary code on the remote host by sending
a specially crafted email." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );



script_end_attributes();

 
 summary["english"] = "Determines the version of Exchange";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

port = get_kb_item ("SMB/transport");

# 2000
if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.0.6618.4") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}
# 2003
else if (version == 65)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if (!sp || sp < 1) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 else if (sp == 2)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7650.29") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 }
 else if (sp == 1)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7233.69") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 }
 
 hotfix_check_fversion_end();
}


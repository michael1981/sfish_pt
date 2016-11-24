#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18680);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2005-2226");
 script_bugtraq_id(14225);
 script_xref(name:"OSVDB", value:"18241");

 name["english"] = "Outlook Express Multiple Vulnerabilities (900930)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A denial of service attack can be launched against the remote Outlook
Express install." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Outlook Express that contains
multiple vulnerabilities. 

An attacker may exploit these vulnerabilities to disable the Outlook
Express client of a victim. 

To exploit these issues, an attacker would need to send a malformed
e-mail message to a victim and wait for him to read it using outlook." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://support.microsoft.com/kb/900930/EN-US/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for Microsoft Hotfix 900930";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-030.nasl");
 script_require_keys("SMB/OutlookExpress/MSOE.dll/Version");
 exit(0);
}


v = get_kb_item("SMB/OutlookExpress/MSOE.dll/Version");
if ( ! v ) exit(0);

vi = split(v, sep:".", keep:0);
if ( int(vi[0]) == 6 && int(vi[1]) == 0 && int(v[2]) < 3790 && int(v[2]) >= 2800 )
{
 if ( int(v[2]) < 2900 || (int(v[2]) == 2900 &&  int(v[3]) < 2670))
	security_warning(port:get_kb_item("SMB/transport"));
}

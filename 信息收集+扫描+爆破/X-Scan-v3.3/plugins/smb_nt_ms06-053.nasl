#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22333);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-0032");
 script_bugtraq_id(19927);
 script_xref(name:"OSVDB", value:"28729");

 name["english"] = "MS06-053: Vulnerability in Indexing Service Could Allow Cross-Site Scripting (920685)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Indexing service that
fails to adequately sanitize some requests.  Combined with a web
server using this service, this flaw could be exploited by an attacker
who would be able to cause arbitrary HTML and script code to be
executed in a user's browser within the security context of the
affected site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-053.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 920685 has been installed";
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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Query.dll", version:"5.2.3790.552", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Query.dll", version:"5.2.3790.2734", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Query.dll", version:"5.1.2600.1860", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Query.dll", version:"5.1.2600.2935", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Query.dll", version:"5.0.2195.7100", dir:"\system32") )
 {
 {
 set_kb_item(name:"SMB/Missing/MS06-053", value:TRUE);
 hotfix_security_note();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
 }
 hotfix_check_fversion_end(); 
 exit (0);
}

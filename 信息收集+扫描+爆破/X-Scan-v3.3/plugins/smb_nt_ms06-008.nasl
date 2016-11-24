#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20908);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-0013");
 script_bugtraq_id(16636);
 script_xref(name:"OSVDB", value:"23134");

 name["english"] = "MS06-008: Vulnerability in Web Client Service Could Allow Remote Code Execution (911927)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Web Client
service that may allow an attacker to execute arbitrary code on the
remote host. 

To exploit this flaw, an attacker would need credentials to log into
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-008.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 911927";
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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Webclnt.dll", version:"5.2.3790.453", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Webclnt.dll", version:"5.2.3790.2591", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Webclnt.dll", version:"5.1.2600.2821", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Webclnt.dll", version:"5.1.2600.1790", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-008", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}


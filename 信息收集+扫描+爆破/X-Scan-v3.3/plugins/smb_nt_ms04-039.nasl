#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15714);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-0892");
 script_xref(name:"IAVA", value:"2004-t-0037");
 script_xref(name:"OSVDB", value:"11579");
 
 name["english"] = "MS04-039: ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to spoof the content of the remote proxy server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ISA Server 2000, an HTTP proxy.  The remote
version of this software is vulnerable to content spoofing attacks. 

An attacker may lure a victim to visit a malicious web site and the
user could believe is visiting a trusted web site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms04-039.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q888258";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.408") == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS04-039", value:TRUE);
  hotfix_security_warning();
 }
 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS04-039", value:TRUE);
  hotfix_security_warning();
 }
}

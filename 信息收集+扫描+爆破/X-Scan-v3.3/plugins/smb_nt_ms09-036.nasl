#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40555);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1536");
  script_bugtraq_id(35985);
  script_xref(name:"OSVDB", value:"56905");

  script_name(english:"MS09-036: Vulnerability in ASP.NET in Microsoft Windows Could Allow Denial of Service (970957)");
  script_summary(english:"Checks version of System.web.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote .Net Framework is susceptible to a denial of service\n",
      "attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
     "The remote host is running a version of the .NET Framework component \n",
      "of Microsoft Windows that is suspectible to a denial of service attack\n",
      "due to the way ASP.NET manages request scheduling.  Using specially\n",
      "crafted anonymous HTTP requests, an anonymous remote attacker can\n",
      "cause the web server to become unresponsive until the associated\n",
      "application pool is restarted.\n",
      "\n",
      "Note that the vulnerable code in the .NET Framework is exposed only\n",
      "through IIS 7.0 when operating in integrated mode."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for .NET Framework 2.0 and\n",
      "3.5 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-036.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (hotfix_check_iis_installed() <= 0) exit(0, "IIS is not installed.");
if (hotfix_check_sp(vista:2) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Can't get system root.");

share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:rootfile);
if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

path = rootfile + "\Microsoft.Net\Framework\v2.0.50727";
if (
  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.4049", min_version:"2.0.50727.4000") == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.3601", min_version:"2.0.50727.3000") == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.1871", min_version:"2.0.50727.0") == HCF_OLDER
)
{
  set_kb_item(name:"SMB/Missing/MS09-036", value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}

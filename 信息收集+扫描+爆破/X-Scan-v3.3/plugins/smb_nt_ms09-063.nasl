#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42437);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2512");
  script_bugtraq_id(36919);
  script_xref(name:"OSVDB", value:"59865");

  script_name(english:"MS09-063: Vulnerability in Web Services on Devices API Could Allow Remote Code Execution (973565)");
  script_summary(english:"Checks version of wsdapi.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the Web
Services for Devices API (WSDAPI)."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a vulnerable version of WSDAPI. 
Sending the affected service a packet with a specially crafted header
can result in arbitrary code execution.  An attacker on the same
subnet could exploit this to take complete control of the system."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms09-063.mspx"
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/10"
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
if (hotfix_check_sp(vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Vista SP0 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6000.16903",   min_version:"6.0.6000.0",     dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6000.21103",   min_version:"6.0.6000.20000", dir:"\system32") ||

  # Vista / 2k8 SP1 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6001.18306",   min_version:"6.0.6001.0",     dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6001.22491",   min_version:"6.0.6001.20000", dir:"\system32") ||

  # Vista / 2k8 SP2 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6002.18085",   min_version:"6.0.6002.0",     dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6002.22194",   min_version:"6.0.6002.20000", dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-063", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}

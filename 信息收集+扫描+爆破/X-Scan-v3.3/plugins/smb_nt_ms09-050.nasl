#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42106);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2526", "CVE-2009-2532", "CVE-2009-3103");
  script_bugtraq_id(36299, 36594, 36595);
  script_xref(name:"OSVDB", value:"57799");
  script_xref(name:"OSVDB", value:"58875");
  script_xref(name:"OSVDB", value:"58876");

  script_name(english:"MS09-050: Vulnerabilities in SMBv2 Could Allow Remote Code Execution (975517)");
  script_summary(english:"Checks version of srv2.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SMB server can be abused to execute code remotely."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host contains a vulnerable SMBv2 implementation\n",
      "with the following issues :\n",
      "\n",
      "  - A specially crafted SMBv2 packet can cause an\n",
      "    infinite loop in the Server service.  A remote,\n",
      "    unauthenticated attacker can exploit this to cause\n",
      "    a denial of service. (CVE-2009-2526)\n",
      "\n",
      "  - Sending a specially crafted SMBv2 packet to the Server\n",
      "    service can result in code execution.  A remote,\n",
      "    unauthenticated attacker can exploit this to take\n",
      "    complete control of the system. (CVE-2009-2532,\n",
      "    CVE-2009-3103)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-050.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/13"
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

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (hotfix_check_sp(vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Vista SP0 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6000.16927",   min_version:"6.0.6000.0", dir:"\system32\drivers") ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6000.21127",   min_version:"6.0.6000.20000", dir:"\system32\drivers") ||

  # Vista / 2k8 SP1 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6001.18331",   min_version:"6.0.6001.0", dir:"\system32\drivers") ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6001.22522",   min_version:"6.0.6001.20000", dir:"\system32\drivers") ||

  # Vista / 2k8 SP2 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6002.18112",   min_version:"6.0.6002.0", dir:"\system32\drivers") ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6002.22225",   min_version:"6.0.6002.20000", dir:"\system32\drivers")
)
{
  set_kb_item(name:"SMB/Missing/MS09-050", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}

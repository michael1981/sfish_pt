#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39794);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1135");
  script_bugtraq_id(35631);
  script_xref(name:"OSVDB", value:"55836");

  script_name(english:"MS09-031: Vulnerability in Microsoft ISA Server 2006 Could Cause Elevation of Privilege (970953)");
  script_summary(english:"Checks version of wspsrv.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains an application that is affected by a\n",
      "privilege escalation vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Microsoft Internet Security and Acceleration (ISA)\n",
      "Server 2006 installed on the remote host may allow an unauthenticated\n",
      "attacker with knowledge of administrator account usernames to gain\n",
      "access to published resources in the context of such a user without\n",
      "having to authenticate with the ISA server.\n",
      "\n",
      "Note that successful exploitation of this issue requires that ISA be\n",
      "configured for Radius One Time Password (OTP) authentication and\n",
      "authentication delegation with Kerberos Constrained Delegation.\n"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for ISA Server 2006 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-031.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);
if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");


if (
  # ISA Server 2006
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5723.514", min_version:"5.0.5723.0") == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5721.263", min_version:"5.0.5721.0") == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5720.174", min_version:"5.0.0.0") == HCF_OLDER
)
{
  set_kb_item(name:"SMB/Missing/MS09-031", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}

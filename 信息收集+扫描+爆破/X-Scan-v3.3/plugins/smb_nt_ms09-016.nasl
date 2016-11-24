#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");
if ( NASL_LEVEL < 3000 ) exit(0);


if (description)
{
  script_id(36154);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-0077", "CVE-2009-0237");
  script_bugtraq_id(34414, 34416);
  script_xref(name:"OSVDB", value:"53636");
  script_xref(name:"OSVDB", value:"53637");

  script_name(english: "MS09-016: Vulnerabilities in Microsoft ISA Server and Forefront Threat Management Gateway Could Cause Denial of Service (961759)");
  script_summary(english:"Checks version of wspsrv.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains an application that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Microsoft ISA Server or Forefront Threat Management\n",
      "Gateway installed on the remote host is affected by one or both of the\n",
      "following vulnerabilities :\n",
      "\n",
      "  - By sending a series of specially crafted packets, an\n",
      "    anonymous remote attacker can create orphaned open\n",
      "    sessions in the firewall engine, thereby denying \n",
      "    service to legitimate users. (CVE-2009-0077)\n",
      "\n",
      "  - A non-persistent cross-site scripting vulnerability\n",
      "    exists in the application due to its failure to sanitize\n",
      "    input to its 'cookieauth.dll' script. (CVE-2009-0237)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for ISA Server 2004 and 2006\n",
      "as well as Forefront Threat Management Gateway :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-016.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/04/14"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/04/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/04/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share())
{
  if (
    # Microsoft Forefront Threat Management Gateway Medium Business Edition
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"6.0.6417.153", min_version:"6.0.0.0") == HCF_OLDER ||

    # ISA Server 2006
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5723.511", min_version:"5.0.5723.0") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5721.261", min_version:"5.0.5721.0") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5720.172", min_version:"5.0.0.0") == HCF_OLDER ||

    # ISA Server 2004
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"4.0.3445.909", min_version:"4.0.3000.0") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"4.0.2167.909") == HCF_OLDER
  ) {
    set_kb_item(name:"SMB/Missing/MS09-016", value:TRUE);
    hotfix_security_warning();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}

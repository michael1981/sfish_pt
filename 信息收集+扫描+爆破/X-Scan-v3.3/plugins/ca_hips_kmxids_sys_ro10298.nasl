#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40621);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2740");
  script_bugtraq_id(36078);
  script_xref(name:"OSVDB", value:"57168");

  script_name(english:"CA Host-Based Intrusion Prevention System Client kmxIds.sys Denial of Service (CA20090818)");
  script_summary(english:"Checks version of kmxIds.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is susceptible to a denial of service attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of the 'kmxIds.sys' driver,\n",
      "a component of CA Host-Based Intrusion Prevention System Client,\n",
      "that does not correctly handle certain malformed network packets.  A\n",
      "remote attacker can leverage this issue to cause a kernel crash."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=214665"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0151.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade as necessary to CA Host-Based Intrusion Prevention System 8.1,\n",
      "install Cumulative Fix 1 RO10298 or later on the CA HIPS server, and\n",
      "ensure that an updated client installation image is installed on\n",
      "each client."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/18"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/18"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/19"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (hotfix_check_fversion(file:"\System32\drivers\kmxIds.sys", version:"7.3.1.18") == HCF_OLDER)
{
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}

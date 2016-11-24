#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39339);
  script_version("$Revision: 1.12 $");

  if (NASL_LEVEL >= 3000)
  {
    script_cve_id(
      "CVE-2006-2783",
      "CVE-2008-1588",
      "CVE-2008-2320",
      "CVE-2008-2321",
      "CVE-2008-3281",
      "CVE-2008-3529",
      "CVE-2008-3632",
      "CVE-2008-4225",
      "CVE-2008-4226",
      "CVE-2008-4231",
      "CVE-2008-4409",
      "CVE-2009-0040",
      "CVE-2009-0145",
      "CVE-2009-0153",
      "CVE-2009-0946",
      "CVE-2009-1179",
      "CVE-2009-1681",
      "CVE-2009-1682",
      "CVE-2009-1684",
      "CVE-2009-1685",
      "CVE-2009-1686",
      "CVE-2009-1687",
      "CVE-2009-1688",
      "CVE-2009-1689",
      "CVE-2009-1690",
      "CVE-2009-1691",
      "CVE-2009-1693",
      "CVE-2009-1694",
      "CVE-2009-1695",
      "CVE-2009-1696",
      "CVE-2009-1697",
      "CVE-2009-1698",
      "CVE-2009-1699",
      "CVE-2009-1700",
      "CVE-2009-1701",
      "CVE-2009-1702",
      "CVE-2009-1703",
      "CVE-2009-1704",
      "CVE-2009-1705",
      "CVE-2009-1706",
      "CVE-2009-1707",
      "CVE-2009-1708",
      "CVE-2009-1709",
      "CVE-2009-1710",
      "CVE-2009-1711",
      "CVE-2009-1712",
      "CVE-2009-1713",
      "CVE-2009-1714",
      "CVE-2009-1715",
      "CVE-2009-1716",
      "CVE-2009-1718",
      "CVE-2009-2027",
      "CVE-2009-2420",
      "CVE-2009-2421"
    );
    script_bugtraq_id(
      30487,
      31092,
      32326,
      33276,
      35260,
      35270,
      35271,
      35272,
      35283,
      35284,
      35308,
      35309,
      35310,
      35311,
      35315,
      35317,
      35318,
      35319,
      35320,
      35321,
      35322,
      35325,
      35327,
      35328,
      35330,
      35331,
      35332,
      35333,
      35334,
      35339,
      35340,
      35344,
      35346,
      35347,
      35348,
      35349,
      35350,
      35351,
      35352,
      35353,
      35481,
      35482
    );
    script_xref(name:"OSVDB", value:"48472");
    script_xref(name:"OSVDB", value:"48569");
    script_xref(name:"OSVDB", value:"49993");
    script_xref(name:"OSVDB", value:"54972");
    script_xref(name:"OSVDB", value:"54973");
    script_xref(name:"OSVDB", value:"54974");
    script_xref(name:"OSVDB", value:"54975");
    script_xref(name:"OSVDB", value:"54981");
    script_xref(name:"OSVDB", value:"54982");
    script_xref(name:"OSVDB", value:"54983");
    script_xref(name:"OSVDB", value:"54984");
    script_xref(name:"OSVDB", value:"54985");
    script_xref(name:"OSVDB", value:"54986");
    script_xref(name:"OSVDB", value:"54987");
    script_xref(name:"OSVDB", value:"54988");
    script_xref(name:"OSVDB", value:"54989");
    script_xref(name:"OSVDB", value:"54990");
    script_xref(name:"OSVDB", value:"54991");
    script_xref(name:"OSVDB", value:"54992");
    script_xref(name:"OSVDB", value:"54993");
    script_xref(name:"OSVDB", value:"54994");
    script_xref(name:"OSVDB", value:"54995");
    script_xref(name:"OSVDB", value:"54996");
    script_xref(name:"OSVDB", value:"54997");
    script_xref(name:"OSVDB", value:"55004");
    script_xref(name:"OSVDB", value:"55005");
    script_xref(name:"OSVDB", value:"55006");
    script_xref(name:"OSVDB", value:"55008");
    script_xref(name:"OSVDB", value:"55009");
    script_xref(name:"OSVDB", value:"55010");
    script_xref(name:"OSVDB", value:"55011");
    script_xref(name:"OSVDB", value:"55012");
    script_xref(name:"OSVDB", value:"55013");
    script_xref(name:"OSVDB", value:"55014");
    script_xref(name:"OSVDB", value:"55015");
    script_xref(name:"OSVDB", value:"55022");
    script_xref(name:"OSVDB", value:"55023");
    script_xref(name:"OSVDB", value:"55027");
    script_xref(name:"OSVDB", value:"55769");
    script_xref(name:"OSVDB", value:"55783");
  }

  script_name(english:"Safari < 4.0");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by several\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Safari installed on the remote Windows host is earlier\n",
      "than 4.0.  Such versions are potentially affected by numerous issues in\n",
      "the following components :\n",
      "\n",
      "  - CFNetwork\n",
      "  - CoreGraphics\n",
      "  - ImageIO\n",
      "  - International Components for Unicode\n",
      "  - libxml\n",
      "  - Safari\n",
      "  - Safari Windows Installer\n",
      "  - WebKit"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3613"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


path = get_kb_item("SMB/Safari/Path");
version = get_kb_item("SMB/Safari/FileVersion");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  (
    ver[0] == 4 &&
    (
      ver[1] < 530 ||
      (ver[1] == 530 && ver[2] < 17)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    prod_version = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_version)) version = prod_version;

    report = string(
      "\n",
      "Nessus collected the following information about the current install\n",
      "of Safari on the remote host :\n",
      "\n",
      "  Version : ", version, "\n",
      "  Path    : ", path, "\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}

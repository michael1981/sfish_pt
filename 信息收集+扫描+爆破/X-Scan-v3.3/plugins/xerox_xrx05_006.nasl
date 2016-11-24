#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(18642);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2200", "CVE-2005-2201", "CVE-2005-2202");
  script_bugtraq_id(14187);
  script_xref(name:"OSVDB", value:"17765");
  script_xref(name:"OSVDB", value:"17766");
  script_xref(name:"OSVDB", value:"17768");

  script_name(english:"XEROX WorkCentre Multiple Vulnerabilities (XRX05-006)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer suffers from multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device with an embedded web server that suffers
from multiple flaws, including authentication bypass, denial of
service, unauthorized file access, and cross-site scripting." );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_006.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_007.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply the P22 patch as described in the XEROX security bulletins." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple remote vulnerabilities in XEROX WorkCentre Pro");
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre");

  exit(0);
}


# This function returns TRUE if the version string ver lies in
# the range [low, high].
function ver_inrange(ver, low, high)
{
  local_var ver_parts, low_parts, high_parts, i, p, low_p, high_p;

  if (isnull(ver) || isnull(low) || isnull(high)) return FALSE;

  # Split levels into parts.
  ver_parts = split(ver, sep:".", keep:0);
  low_parts = split(low, sep:".", keep:0);
  high_parts = split(high, sep:".", keep:0);

  # Compare each part.
  i = 0;
  while (ver_parts[i] != NULL)
  {
    p = int(ver_parts[i]);
    low_p = int(low_parts[i]);
    if (low_p == NULL) low_p = 0;
    high_p = int(high_parts[i]);
    if (high_p == NULL) high_p = 0;

    if (p > low_p && p < high_p) return TRUE;
    if (p < low_p || p > high_p) return FALSE;
    ++i;
  }
  return TRUE;
}


# Check whether the device is vulnerable.
if (get_kb_item("www/xerox_workcentre"))
{
  model = get_kb_item("www/xerox_workcentre/model");
  ssw = get_kb_item("www/xerox_workcentre/ssw");

  # No need to check further if ESS has with ".P22" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P22[^0-9]?") exit(0);

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    # nb: models Pro 2128/2636/3545 Color with SSW 0.001.04.044 - 0.001.04.504.
    model =~ "Pro (32|40)C" && ver_inrange(ver:ssw, low:"0.001.04.044", high:"0.001.04.504")
  ) security_hole(0);
}

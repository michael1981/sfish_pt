#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29965);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-2446", "CVE-2007-2447");
  script_bugtraq_id(23972, 23973, 24195, 24196, 24197, 24198);
  script_xref(name:"OSVDB", value:"34700");
  script_xref(name:"OSVDB", value:"34732");

  script_name(english:"XEROX WorkCentre Multiple Samba Vulnerabilities (XRX08-001)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

 script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device that reportedly is affected by multiple
buffer overflow and remote command injection issues in the file and
print sharing code the ESS / Network Controller.  Using
specially-crafted RPC requests, an unauthenticated attacker could
leverage these issues to run arbitrary code on the affected device or
make unauthorized changes to its system configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX08_001.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply the P32 patch as described in the XEROX security bulletin
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  ess = get_kb_item("www/xerox_workcentre/ess");

  # No need to check further if ESS has ".P32" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P32") exit(0);

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    (
      # nb: models 232/238/245/255/265/275 with ESS in [0, 040.022.1110).
      (model =~ "^2(3[28]|[4-7]5)" || model =~ "Pro 2(3[28]|[4-7]5)") && 
      ver_inrange(ver:ess, low:"0.0.0", high:"040.022.1109")
    ) ||
    (
      # nb: models 7655/7665 with ESS in [0, 040.032.55080).
      (model =~ "^76[56]5") && 
      ver_inrange(ver:ess, low:"0.0.0", high:"040.032.55079")
    )
  ) security_hole(0);
}

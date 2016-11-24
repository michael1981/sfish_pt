#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34244);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-1105");
  script_bugtraq_id(29404);
  script_xref(name:"OSVDB", value:"45657");

  script_name(english:"XEROX WorkCentre Samba Overflow (XRX08-009)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

 script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device allows execution of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device that reportedly allows a remote attacker
to execute arbitrary code via specially crafted Service Message Block
(SMB) responses due to vulnerabilities in the third-party code it uses
to handle file and printer sharing services for SMB clients" );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX08_009.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply the P36v1 patch as described in the XEROX security bulletin
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
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
  ssw = get_kb_item("www/xerox_workcentre/ssw");
  if (ssw && "." >< ssw) ssw = strstr(ssw, ".") - ".";
  ess = get_kb_item("www/xerox_workcentre/ess");

  # No need to check further if ESS has ".P36v1" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P36v1") exit(0);

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    (
      # nb: models 232/238/245/255/265/275/287 with SSW in [0, *.60.22.016).
      model =~ "^(Pro )?2(3[28]|[4-7]5|87)" && 
      # nb: the leading part of the System SW has already been removed.
      ver_inrange(ver:ssw, low:"0.0.0", high:"60.22.015")
    ) ||
    (
      # nb: models 7655/7665/7675 with ESS in [0, 040.033.53050).
      model =~ "^76[567]5" && 
      ver_inrange(ver:ess, low:"0.0.0", high:"040.033.53049")
    ) ||
    (
      # nb: models 5632/5635/5645/5655/5665/5675/5687 with ESS in [0, 050.060.50920).
      model =~ "^56(32|[3-7]5|87)" && 
      ver_inrange(ver:ess, low:"0.0.0", high:"050.060.50919")
    )
  ) security_hole(0);
}

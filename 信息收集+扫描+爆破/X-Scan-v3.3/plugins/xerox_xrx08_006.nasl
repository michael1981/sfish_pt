#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33167);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-2824");
  script_bugtraq_id(29691);
  script_xref(name:"OSVDB", value:"46138");
  script_xref(name:"Secunia", value:"30670");

  script_name(english:"XEROX WorkCenter Extensible Interface Platform Unspecified Security Bypass (XRX08-006)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

 script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device that reportedly contains a unspecified
vulnerability affecting the Extensible Interface Platform feature in
the products Web Services.  A remote attacker may be able to leverage
this issue to make changes to the system configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX08_006.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply the P34 patch as described in the XEROX security bulletin
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

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

  # No need to check further if ESS has ".P34" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P34") exit(0);

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    # nb: models 7655/7665/7675 with ESS in [0, 040.033.53011).
    (model =~ "^76[567]5") && 
    ver_inrange(ver:ess, low:"0.0.0", high:"040.033.53010")
  ) security_hole(0);
}

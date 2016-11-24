#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25637);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_bugtraq_id(20246, 20247, 20248, 20249);
  script_xref(name:"OSVDB", value:"29260");
  script_xref(name:"OSVDB", value:"29261");
  script_xref(name:"OSVDB", value:"29262");
  script_xref(name:"OSVDB", value:"29263");

  script_name(english:"XEROX WorkCentre Multiple OpenSSL Vulnerabilities (XRX07-001)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

 script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device that reportedly suffers from multiple
issues in the ESS / Network Controller that could allow remote
execution of arbitrary code on the affected device, initiation of
denial-of-service attacks, and forgery of digital certificates." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99fdc232" );
 script_set_attribute(attribute:"solution", value:
"Apply the P30 patch as described in the XEROX security bulletin
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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

  # No need to check further if ESS has ".P30" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P30") exit(0);

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    (
      # nb: models 232/238/245/255/265/275 with ESS in [0, 040.022.00115).
      (model =~ "^2(3[28]|[4-7]5)" || model =~ "Pro 2(3[28]|[4-7]5)") && 
      ver_inrange(ver:ess, low:"0.0.0", high:"040.022.1031")
    ) ||
    (
      # nb: models 7655/7665 with ESS in [0, 040.032.53080].
      (model =~ "^76[56]5") && 
      ver_inrange(ver:ess, low:"0.0.0", high:"040.032.53081")
    )
  ) security_hole(0);
}

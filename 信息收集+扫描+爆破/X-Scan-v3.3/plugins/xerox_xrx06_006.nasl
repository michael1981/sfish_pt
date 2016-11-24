#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23751);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-6427", "CVE-2006-6428", "CVE-2006-6429", "CVE-2006-6430", "CVE-2006-6431", "CVE-2006-6432");
  script_bugtraq_id(21365);
  script_xref(name:"OSVDB", value:"31803");
  script_xref(name:"OSVDB", value:"31804");
  script_xref(name:"OSVDB", value:"31805");
  script_xref(name:"OSVDB", value:"31806");
  script_xref(name:"OSVDB", value:"31807");
  script_xref(name:"OSVDB", value:"31808");
  script_xref(name:"OSVDB", value:"31809");
  script_xref(name:"OSVDB", value:"31810");

  script_name(english:"XEROX WorkCentre Multiple Vulnerabilities (XRX06-006)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

 script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its model number and software versions, the remote host
is a XEROX WorkCentre device that reportedly suffers from multiple
issues such as command injection and information disclosure
vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX06_006_v1b.pdf" );
 script_set_attribute(attribute:"solution", value:
"Update to System Software Version 12.060.17.000, 13.060.17.000, or
14.060.17.000 as appropriate." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    # nb: models 232/238/245/255/265/275 with ESS in [0, 040.022.00115).
    (model =~ "^2(3[28]|[4-7]5)" || model =~ "Pro 2(3[28]|[4-7]5)") && 
    ver_inrange(ver:ess, low:"0.0.0", high:"040.022.00114")
  ) security_hole(0);
}

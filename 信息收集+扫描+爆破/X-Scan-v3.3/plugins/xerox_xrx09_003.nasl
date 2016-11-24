#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40807);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(36177);
  script_xref(name:"OSVDB", value:"57569");

  script_name(english:"XEROX WorkCentre Web Services Extensible Interface Platform Unauthorized Access (XRX09-003)");
  script_summary(english:"Checks Net Controller Software version of XEROX WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote multi-function device may allow unauthorized access."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "According to its model number and software versions, the remote host\n",
      "is a XEROX WorkCentre device that may allow a remote attacker to\n",
      "obtain unauthorized access to device configuration settings, possibly\n",
      "exposing customer passwords.\n",
      "\n",
      "Note that success exploitation requires that SSL is not enabled for\n",
      "the web server component."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX09-003_v1.2.pdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Apply the P39 patch as described in the XEROX security bulletin\n",
      "referenced above."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/28"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/28"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
  if (isnull(model)) exit(1, "The 'www/xerox_workcentre/model' KB item is missing.");
  ssw = get_kb_item("www/xerox_workcentre/ssw");
  if (ssw && "." >< ssw) ssw = strstr(ssw, ".") - ".";
  ess = get_kb_item("www/xerox_workcentre/ess");
  if (isnull(ess)) exit(1, "The 'www/xerox_workcentre/ess' KB item is missing.");

  # No need to check further if ESS has ".P39v2" since that
  # indicates the patch has already been applied.
  if (ess && ".P39v2" >< ess) exit(0, "The host is not affected - the patch has already been applied.");

  # Test model number and software version against those in XEROX's security bulletin.
  if (
    (
      # nb: models 5632/5638/5645/5655/5665/5675/5687 with ESS in [060.108.35300, 060.109.10507] or [060.068.25600, 060.069.10508].
      model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" && 
      (
        ver_inrange(ver:ess, low:"060.108.35300", high:"060.109.10507") ||
        ver_inrange(ver:ess, low:"060.068.25600", high:"060.069.10508")
      )
    )
  ) security_warning(0);
  else exit(0, "The host is not affected.");
}
else exit(1, "The 'www/xerox_workcentre' KB item is missing.");

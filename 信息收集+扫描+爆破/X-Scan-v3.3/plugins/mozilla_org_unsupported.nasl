#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(40362);
  script_version("$Revision: 1.2 $");

  script_name(english:"Mozilla Foundation Unsupported Application Detection");
  script_summary(english:"Checks if any Mozilla app versions are unsupported");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains one or more unsupported applications from\n",
      "the Mozilla Foundation."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its version, there is at least one unsupported version\n",
      "of a Mozilla application on the remote host.  The following versions\n",
      "of Mozilla applications are no longer supported :\n\n",
      "  Firefox :\n",
      "  - 0.x\n",
      "  - 1.0.x\n",
      "  - 1.5.x\n",
      "  - 2.0.x\n\n",
      "  Thunderbird :\n",
      "  - 0.x\n",
      "  - 1.0.x\n",
      "  - 1.5.x\n\n",
      "  SeaMonkey :\n",
      "  - 0.x\n",
      "  - 1.0.x\n\n",
      "These versions have publicly known security vulnerabilities, but are\n",
      "no longer maintained by Mozilla."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.com/en-US/firefox/upgrade.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozillamessaging.com/en-US/thunderbird/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.seamonkey-project.org/releases/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to an actively maintained version."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/24"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# KVPs of unsupported installs detected.
# product/version => path(s) (pipe delimited)
vuln = make_array();

# Checks if the version of the given app is unsupported, and if so, adds
# product, version number, and installation path to 'vuln'
function mozilla_unsupported(kb_key, path)
{
  local_var unsupported, match, product, ver, ver_fields, prod_ver;
  unsupported = FALSE;

  # bail out if we can't for whatever reason get the product or version number
  match = eregmatch(string:kb_key, pattern:'/([a-zA-z]+)/([0-9.]+)$');
  if (isnull(match)) return;

  product = match[1];
  ver = match[2];
  ver_fields = split(ver, sep:'.', keep:FALSE);

  if (product == 'Firefox') unsupported = firefox_unsupported(ver_fields);
  if (product == 'Thunderbird') unsupported = thunderbird_unsupported(ver_fields);
  if (product == 'SeaMonkey') unsupported = seamonkey_unsupported(ver_fields);

  if (unsupported)
  {
    set_kb_item(name:"Mozilla/" + product + "/Unsupported", value:ver);
    prod_ver = string(product, " ", ver);
    if (vuln[prod_ver]) vuln[prod_ver] += string("|", path);
    else vuln[prod_ver] = path;
  }
}

# unsupported Firefox versions:
# 0.x
# 1.0.x (Basically
# 1.5.x  1.x)
# 2.0.x (Basically 2.x)
function firefox_unsupported()
{
  local_var ver;
  ver = _FCT_ANON_ARGS[0];

  if (ver[0] == 0 || ver[0] == 1 || ver[0] == 2) return TRUE;
  else return FALSE;
}

# unsupported Thunderbird versions:
# 0.x
# 1.0.x (basically
# 1.5.x  1.x)
function thunderbird_unsupported()
{
  local_var ver;
  ver = _FCT_ANON_ARGS[0];

  if (ver[0] == 0 || ver[0] == 1) return TRUE;
  else return FALSE;
}

# unsupported SeaMonkey versions:
# 0.x
# 1.0.x
function seamonkey_unsupported()
{
  local_var ver;
  ver = _FCT_ANON_ARGS[0];

  if (ver[0] == 0 || (ver[0] == 1 && ver[1] == 0)) return TRUE;
  else return FALSE;
}

#
# Execution begins here
#

# Firefox/Thunderbird install info is saved in a different location than
# SeaMonkey info in the KB, so we need to do 2 gets and 2 iterations
mozilla_installs = get_kb_list("SMB/Mozilla/*");
seamonkey_installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(mozilla_installs) && isnull(seamonkey_installs))
  exit(0, "No Mozilla products were detected.");

# See if any installs are unsupported...
foreach key (keys(mozilla_installs))
  mozilla_unsupported(kb_key:key, path:mozilla_installs[key]);

foreach key (keys(seamonkey_installs))
  mozilla_unsupported(kb_key:key, path:seamonkey_installs[key]);

# ...then report on them
if (max_index(keys(vuln)))
{
  port = get_kb_item("SMB/transport");
  report = string(
    "\n",
    "The following unsupported Mozilla applications were detected :\n"
  );

  foreach prod_ver (sort(keys(vuln)))
  {
    report += string(
      "\n",
      "  - ", prod_ver, " installed under\n"
    );

    paths = split(vuln[prod_ver], sep:'|', keep:FALSE);

    foreach path (paths)
      report += string("    ", path, "\n");
  }

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else exit(0, "No unsupported versions were detected.");

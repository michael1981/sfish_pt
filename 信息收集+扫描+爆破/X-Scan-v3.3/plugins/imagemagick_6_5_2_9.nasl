#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38951);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1882");
  script_bugtraq_id(35111);
  script_xref(name:"OSVDB", value:"54729");
  script_xref(name:"Secunia", value:"35216");

  script_name(english:"ImageMagick < 6.5.2-9 magick/xwindow.c XMakeImage() Function TIFF File Handling Overflow");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
an integer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick earlier
than 6.5.2-9.  Such versions reportedly fail to properly handle
malformed 'TIFF' files in the 'XMakeImage()' function.  If an attacker
can trick a user on the remote host into opening a specially crafted
file using the affected application, he can leverage this flaw to
execute arbitrary code on the remote host subject to the user's
privileges." );
  script_set_attribute(attribute:"see_also", value:"http://mirror1.smudge-it.co.uk/imagemagick/www/changelog.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick 6.5.2-9 or later as this reportedly fixes the 
issue." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("SMB/ImageMagick/Installed");
  exit(0);
}

#

include("global_settings.inc");

# Check each installation
installs = get_kb_list("SMB/ImageMagick/*");
if (isnull(installs)) exit(0);

info = "";
vulns = make_array();

foreach install (sort(keys(installs)))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/ImageMagick/";
  if (version =~ "^ImageMagick [0-5]\.|6\.([0-4]\.|5\.([01](-|$)|2(-[0-8]$|$)))")
  {
    path = installs[install];

    if (vulns[version]) vulns[version] += ";" + path;
    else vulns[version] = path;
  }
}

if (max_index(keys(vulns)))
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(vulns)))
    {
      info += '  ' + version + ', installed under :\n';

      foreach path (sort(split(vulns[version], sep:";", keep:FALSE)))
      {
        n++;
        info += '    - ' + path + '\n';
      }
    }
    info += '\n';

    if (n > 1) s = "s of ImageMagick are";
    else s = " of ImageMagick is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on\n",
      "the remote host :\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}

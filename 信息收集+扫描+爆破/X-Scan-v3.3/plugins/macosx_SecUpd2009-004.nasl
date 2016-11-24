#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(40591);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0696");
  script_bugtraq_id(35848);
  script_xref(name:"OSVDB", value:"56584");

  script_name(english:"Mac OS X BIND Dynamic Update Message Handling Remote DoS (Security Update 2009-004)");
  script_summary(english:"Check for the presence of Security Update 2009-004");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is missing a Mac OS X update that fixes a denial of\n",
      "service issue."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running a version of Mac OS X 10.5 or 10.4 that\n",
      "does not have Security Update 2009-004 applied.\n",
      "\n",
      "This security update contains a fix for the following product :\n",
      "\n",
      "  - bind"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3776"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/aug/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-004 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/12"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/13"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}

#

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

  if (!egrep(pattern:"^SecUpd(Srvr)?(2009-00[4-5]|20[1-9][0-9]-)", string:packages))
    security_warning(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-8]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2009\.004\.bom", string:packages))
    security_warning(0);
}
else exit(0, "The host is not affected.");

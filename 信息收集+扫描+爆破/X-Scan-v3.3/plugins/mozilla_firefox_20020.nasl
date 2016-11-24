#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35251);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-5507");
  script_xref(name:"OSVDB", value:"51292");

  script_name(english:"Firefox < 2.0.0.20 Cross Domain Data Theft");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
cross domain data theft vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 2.0.0.20.  Such
versions shipped without a fix for a security issue that was
reportedly fixed in version 2.0.0.19. Specifically :

  - A website may be able to access a limited amount of 
    data from a different domain by loading a same-domain 
    JavaScript URL which redirects to an off-domain target
    resource containing data which is not parsable as 
    JavaScript. (MFSA 2008-65)

Note that Mozilla is not planning further security / stability
updates for Firefox 2." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f23d29d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.20." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 20)
) security_warning(get_kb_item("SMB/transport"));

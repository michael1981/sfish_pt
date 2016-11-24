#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from Tenable Network Security
#
#  Ref: Max <spamhole@gmx.at>
#
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, output formatting & touch-ups, OSVDB ref (10/26/09)


include("compat.inc");

if(description)
{
 script_id(15432);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0906");
 script_bugtraq_id(11166);
 script_xref(name:"OSVDB", value:"10559");

 script_name(english:"Mozilla Multiple Products XPInstall Arbitrary File Overwrite");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a web-browser installed that has file
permissions set incorrectly." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla and/or Firefox, an alternative web 
browser.

The version of this software is prone to an improper file permission
setting.

This flaw only exists if the browser is installed by the Mozilla 
Foundation package management, thus this alert might be a false 
positive.

A local attacker could overwrite arbitrary files or execute arbitrary
code in the context of the user running the browser." );
 script_set_attribute(attribute:"see_also", value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:107" );
 script_set_attribute(attribute:"see_also", value:"http://www.suse.de/de/security/2004_36_mozilla.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines the version of Mozilla/Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 if ( NASL_LEVEL >= 3206 )script_require_ports("Mozilla/Version", "Mozilla/Firefox/Version");
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Version");
if (!isnull(ver)) 
{
  if (
    ver[0] < 1 ||
    (
      ver[0] == 1 &&
      (
        ver[1] < 7 ||
        (ver[1] == 7 && ver[2] < 3)
      )
    )
  )  security_hole(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (ver[0] == 0)security_hole(get_kb_item("SMB/transport"));
}

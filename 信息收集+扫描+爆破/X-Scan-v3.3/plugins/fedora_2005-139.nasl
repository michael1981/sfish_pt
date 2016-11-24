#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16373);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0088");
 
 name["english"] = "Fedora Core 2 2005-139: mod_python";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-139 (mod_python).

Mod_python is a module that embeds the Python language interpreter
within
the server, allowing Apache handlers to be written in Python.

Mod_python brings together the versatility of Python and the power of
the Apache Web server for a considerable boost in flexibility and
performance over the traditional CGI approach.

Update Information:

Graham Dumpleton discovered a flaw affecting the publisher handler of
mod_python, used to make objects inside modules callable via URL.
A remote user could visit a carefully crafted URL that would gain
access to
objects that should not be visible, leading to an information leak.
The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned
the name CVE-2005-0088 to this issue.

This update includes a patch which fixes this issue." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=391" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the mod_python package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mod_python-3.1.3-1.fc2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_python-debuginfo-3.1.3-1.fc2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"mod_python-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0088", value:TRUE);
}

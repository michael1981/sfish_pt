
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1669
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31080);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-1669: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1669 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
ChangeLog:


Update information :

* Fri Feb  8 2008 Kai Engert <kengert redhat com> - 1.1.8-1
- SeaMonkey 1.1.8
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.8-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

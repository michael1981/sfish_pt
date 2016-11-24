
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2417
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38079);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-2417: bugzilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2417 (bugzilla)");
 script_set_attribute(attribute: "description", value: "Bugzilla is a popular bug tracking system used by multiple open source projects
It requires a database engine installed - either MySQL, PostgreSQL or Oracle.
Without one of these database engines (local or remote), Bugzilla will not work
- see the Release Notes for details.

-
ChangeLog:


Update information :

* Thu Mar  5 2009 Itamar Reis Peixoto <itamar ispbrasil com br> 3.2.2-2
- fix from BZ #474250 Comment #16, from Chris Eveleigh -->
- add python BR for contrib subpackage
- fix description
- change Requires perl-SOAP-Lite to perl(SOAP::Lite) according guidelines
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4437", "CVE-2008-6098", "CVE-2009-0481", "CVE-2009-0482", "CVE-2009-0483", "CVE-2009-0484", "CVE-2009-0485", "CVE-2009-0486");
script_summary(english: "Check for the version of the bugzilla package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"bugzilla-3.2.2-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

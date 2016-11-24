
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6833
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33767);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6833: trac");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6833 (trac)");
 script_set_attribute(attribute: "description", value: "Trac is an integrated system for managing software projects, an
enhanced wiki, a flexible web-based issue tracker, and an interface to
the Subversion revision control system.  At the core of Trac lies an
integrated wiki and issue/bug database. Using wiki markup, all objects
managed by Trac can directly link to other issues/bug reports, code
changesets, documentation and files.  Around the core lies other
modules, providing additional features and tools to make software
development more streamlined and effective.

-
Update Information:

Update to 0.10.5 to fix two non-critical security issues:    CVE-2008-2951:
Open redirect vulnerability in the search script in Trac before 0.10.5 allows
remote attackers to redirect users to arbitrary web sites and conduct phishing
attacks via a URL in the q parameter.    CVE-2008-3328:  Cross-site scripting
(XSS) vulnerability in the wiki engine in Trac before 0.10.5 allows remote
attackers to inject arbitrary web script or HTML via unknown vectors.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2951", "CVE-2008-3328");
script_summary(english: "Check for the version of the trac package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"trac-0.10.5-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

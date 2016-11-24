
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9505
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40956);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-9505: epiphany-extensions");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9505 (epiphany-extensions)");
 script_set_attribute(attribute: "description", value: "Epiphany Extensions is a collection of extensions for Epiphany, the
GNOME web browser.

-
Update Information:

Update to new upstream Firefox version 3.5.3, fixing multiple security issues
detailed in the upstream advisories:    [9]http://www.mozilla.org/security/know
n-
vulnerabilities/firefox35.html#firefox3.5.3    Update also includes all package
s
depending on gecko-libs rebuilt against new version of Firefox / XULRunner.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
script_summary(english: "Check for the version of the epiphany-extensions package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"epiphany-extensions-2.26.1-6.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

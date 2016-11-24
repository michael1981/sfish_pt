
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4183
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32408);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-4183: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4183 (gnutls)");
 script_set_attribute(attribute: "description", value: "GnuTLS is a project that aims to develop a library which provides a secure
layer, over a reliable transport layer. Currently the GnuTLS library implements
the proposed standards by the IETF's TLS working group.

-
Update Information:

Fixes critical security issue GNUTLS-SA-2008-1 described here:
[9]http://lists.gnu.org/archive/html/gnutls-devel/2008-05/msg00060.html    All
applications and system services which utilize gnutls library must be restarted
for the updates to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
script_summary(english: "Check for the version of the gnutls package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gnutls-1.6.3-3.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

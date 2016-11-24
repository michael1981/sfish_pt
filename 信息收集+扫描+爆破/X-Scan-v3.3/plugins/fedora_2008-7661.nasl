
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7661
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34422);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 9 2008-7661: neon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7661 (neon)");
 script_set_attribute(attribute: "description", value: "neon is an HTTP and WebDAV client library, with a C interface;
providing a high-level interface to HTTP and WebDAV methods along
with a low-level interface for HTTP request handling.  neon
supports persistent connections, proxy servers, basic, digest and
Kerberos authentication, and has complete SSL support.

-
Update Information:

This update includes the latest release of neon, fixing a security issue in the
Digest authentication domain parameter support.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3746");
script_summary(english: "Check for the version of the neon package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"neon-0.28.3-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

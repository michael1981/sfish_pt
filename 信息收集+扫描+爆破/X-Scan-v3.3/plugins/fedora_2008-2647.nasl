
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2647
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31670);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2647: krb5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2647 (krb5)");
 script_set_attribute(attribute: "description", value: "Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

-
Update Information:

This update incorporates fixes included in MITKRB5-SA-2008-001 (use of
uninitialized pointer / double-free in the KDC when v4 compatibility is enabled
)
and MITKRB5-SA-2008-002 (incorrect handling of high-numbered descriptors in the
RPC library).    This update also incorporates less-critical fixes for a double
-
free (CVE-2007-5971) and an incorrect attempt to free non-heap memory
(CVE-2007-5901) in the GSSAPI library.    This update also fixes an incorrect
calculation of the length of the absolute path name of a file when the relative
path is known and the library needs to look up which SELinux label to apply to
the file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
script_summary(english: "Check for the version of the krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"krb5-1.6.2-14.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

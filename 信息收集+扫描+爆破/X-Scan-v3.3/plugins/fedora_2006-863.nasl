
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-863
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24162);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-863: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-863 (httpd)");
 script_set_attribute(attribute: "description", value: "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

Update Information:

This update fixes a security issue in the mod_rewrite module.

Mark Dowd of McAfee Avert Labs reported an off-by-one
security problem in the LDAP scheme handling of the
mod_rewrite module. Where RewriteEngine was enabled, and for
certain RewriteRules, this could lead to a pointer being
written out of bounds. (CVE-2006-3747)

The ability to exploit this issue is dependent on the stack
layout for a particular compiled version of mod_rewrite.
The Fedora project has analyzed Fedora Core 4 and 5 binaries
and determined that these distributions are vulnerable to
this issue. However this flaw does not affect a default
installation of Fedora Core; users who do not use, or have
not enabled, the Rewrite module are not affected by this
issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-3747");
script_summary(english: "Check for the version of the httpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"httpd-devel-2.2.2-1.2", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.2.2-1.2", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.2-1.2", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.2-1.2", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

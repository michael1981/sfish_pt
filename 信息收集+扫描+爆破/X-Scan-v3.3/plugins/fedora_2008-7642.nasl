
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7642
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34139);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-7642: adminutil");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7642 (adminutil)");
 script_set_attribute(attribute: "description", value: "adminutil is libraries of functions used to administer directory
servers, usually in conjunction with the admin server.  adminutil is
broken into two libraries - libadminutil contains the basic
functionality, and libadmsslutil contains SSL versions and wrappers
around the basic functions.  The PSET functions allow applications to
store their preferences and configuration parameters in LDAP, without
having to know anything about LDAP.  The configuration is cached in a
local file, allowing applications to function even if the LDAP server
is down.  The other code is typically used by CGI programs used for
directory server management, containing GET/POST processing code as
well as resource handling (ICU ures API).

-
Update Information:

Fixes these bugs:    - CVE-2008-2928 - buffer overflow in Accept-Language
parsing    413531 Web browser accepted languages configuration causes dsgw CGI
binaries to segfault    - improved fix for CVE-2008-2929 XSS issues (originally
addressed in 1.1.6), that does not introduce heap overflow in parsing %-encoded
inputs (CVE-2008-2932)    245248 dsgw doesn't escape filename in error message
454060 ViewLog CGI crash with new adminutil 1.1.6
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2928", "CVE-2008-2929", "CVE-2008-2932");
script_summary(english: "Check for the version of the adminutil package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"adminutil-1.1.7-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

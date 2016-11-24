
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10539
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42158);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10539: perl-Net-OAuth");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10539 (perl-Net-OAuth)");
 script_set_attribute(attribute: "description", value: "Perl implementation of OAuth, an open protocol to allow secure API
authentication in a simple and standard method from desktop and web
applications. In practical terms, a mechanism for a Consumer to request
protected resources from a Service Provider on behalf of a user.

-
Update Information:

A session fixation vulnerability was discovered in OAuth protocol 1.0. Perl
OAuth bindings were updated to support the new version of the OAauth protocol
that was issued to address the vulnerability.    All OAuth users are strongly
advised to update to this updated package and protocol version 1.0a which fixes
the vulnerability.    Upstream advisory: [9]http://oauth.net/advisories/2009-1
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the perl-Net-OAuth package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Net-OAuth-0.19-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

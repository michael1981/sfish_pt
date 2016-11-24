
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0544
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36222);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 10 2009-0544: ntp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0544 (ntp)");
 script_set_attribute(attribute: "description", value: "The Network Time Protocol (NTP) is used to synchronize a computer's
time with another reference time source. This package includes ntpd
(a daemon which continuously adjusts system time) and utilities used
to query and configure the ntpd daemon.

Perl scripts ntp-wait and ntptrace are in the ntp-perl package and
the ntpdate program is in the ntpdate package.

-
Update Information:

This update fixes CVE-2009-0021:    NTP 4.2.4 before 4.2.4p5 and 4.2.5 before
4.2.5p150 does not properly check the return value from the OpenSSL
EVP_VerifyFinal function, which allows remote attackers to bypass validation of
the certificate chain via a malformed SSL/TLS signature for DSA and ECDSA keys,
a similar vulnerability to CVE-2008-5077.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5077", "CVE-2009-0021");
script_summary(english: "Check for the version of the ntp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ntp-4.2.4p6-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

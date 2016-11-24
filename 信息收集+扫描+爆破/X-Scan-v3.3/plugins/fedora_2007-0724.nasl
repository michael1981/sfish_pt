
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0724
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27676);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-0724: c-ares");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0724 (c-ares)");
 script_set_attribute(attribute: "description", value: "c-ares is a C library that performs DNS requests and name resolves
asynchronously. c-ares is a fork of the library named 'ares', written
by Greg Hudson at MIT.

-
Update Information:

There is a vulnerability in c-ares < 1.4.0, caused by predictable DNS 'Transact
ion ID' field in DNS queries and can be exploited to poison the DNS cache of an
application using the library if a valid ID is guessed.

[8]http://www.vuxml.org/freebsd/70ae62b0-16b0-11dc-b803-0016179b2dd5.html

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3152", "CVE-2007-3153");
script_summary(english: "Check for the version of the c-ares package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"c-ares-1.4.0-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

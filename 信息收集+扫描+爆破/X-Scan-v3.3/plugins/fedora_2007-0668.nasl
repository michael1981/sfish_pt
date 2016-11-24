
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0668
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27673);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-0668: perl-Net-DNS");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0668 (perl-Net-DNS)");
 script_set_attribute(attribute: "description", value: "Net::DNS is a collection of Perl modules that act as a Domain Name
System (DNS) resolver. It allows the programmer to perform DNS queries
that are beyond the capabilities of gethostbyname and gethostbyaddr.

The programmer should be somewhat familiar with the format of a DNS
packet and its various sections. See RFC 1035 or DNS and BIND (Albitz
& Liu) for details.

-
Update Information:

This brings F-7 up to date with the latest changes to
Net::DNS. See the project page here:

[8]http://search.cpan.org/~olaf/Net-DNS-0.60/

The change for this upstream issue is included:

[9]http://rt.cpan.org/Public/Bug/Display.html?id=23961

Since this fix has security implications (making DNS
spoofing more difficult), pushing updates to all current
versions of fedora.

Note - I know of no exploits for the security issue
described above.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the perl-Net-DNS package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Net-DNS-0.60-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

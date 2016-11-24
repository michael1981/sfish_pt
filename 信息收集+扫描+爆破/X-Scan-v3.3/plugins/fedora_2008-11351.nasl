
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11351
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37488);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-11351: avahi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11351 (avahi)");
 script_set_attribute(attribute: "description", value: "Avahi is a system which facilitates service discovery on
a local network -- this means that you can plug your laptop or
computer into a network and instantly be able to view other people who
you can chat with, find printers to print to or find files being
shared. This kind of technology is already found in MacOS X (branded
'Rendezvous', 'Bonjour' and sometimes 'ZeroConf') and is very
convenient.

-
Update Information:

This version includes five patches backported from the recently released 0.6.24
:
- A trivial security fix for CVE-2008-5081, rhbz 475964.    - A trivial fix for
the threaded event loop, avahi bts #251    - A trivial fix unbreaking the
--force-bind logic of avahi-autoipd, avahi bts #209    - A trivial fix to make
sure we never end up with an invalid IP address in avahi-autoipd, avahi bts #23
1
- A trivial change to include the host name of the sender when we receive bogus
mDNS packets, rhbz #438013    All changes are 'trivial', i.e. very simple in
nature.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5081");
script_summary(english: "Check for the version of the avahi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"avahi-0.6.22-12.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

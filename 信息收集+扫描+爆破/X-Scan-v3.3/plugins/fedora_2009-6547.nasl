
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6547
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39543);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-6547: rb_libtorrent");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6547 (rb_libtorrent)");
 script_set_attribute(attribute: "description", value: "rb_libtorrent is a C++ library that aims to be a good alternative to all
the other BitTorrent implementations around. It is a library and not a full
featured client, although it comes with a few working example clients.

Its main goals are to be very efficient (in terms of CPU and memory usage) as
well as being very easy to use both as a user and developer.

-
Update Information:

This release adds an upstream patch to fix a directory traversal vulnerability
which would allow a remote attacker to create or overwrite arbitrary files via
a
'..' (dot dot) and partial relative pathname in a specially-crafted torrent.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1760");
script_summary(english: "Check for the version of the rb_libtorrent package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"rb_libtorrent-0.13.1-5.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

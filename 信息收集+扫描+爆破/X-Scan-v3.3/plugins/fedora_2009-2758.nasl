
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2758
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37264);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-2758: mldonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2758 (mldonkey)");
 script_set_attribute(attribute: "description", value: "MLDonkey is a door to the 'donkey' network, a decentralized network used to
exchange big files on the Internet. It is written in a wonderful language,
called Objective-Caml, and present most features of the basic Windows donkey
client, plus some more:
- It should work on most UNIX-compatible platforms.
- You can remotely command your client, either by telnet (port 4000),
by a WEB browser ([9]http://localhost:4080), or with a classical client
interface (see [10]http://www.nongnu.org/mldonkey)
- You can connect to several servers, and each search will query all the
connected servers.
- You can select mp3s by bitrates in queries (useful ?).
- You can select the name of a downloaded file before moving it to your
incoming directory.
- You can have several queries in the graphical user interface at the same
time.
- You can remember your old queries results in the command-line interface.
- You can search in the history of all files you have seen on the network.

It can also access other peer-to-peer networks:
- BitTorrent
- Fasttrack
- FileTP (wget-clone)
- DC++

-
Update Information:


Update information :

* Fix local file access bug in internal http server  * Optimized implementation
of the ip_set module
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0753");
script_summary(english: "Check for the version of the mldonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mldonkey-3.0.0-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16288);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0096", "CVE-2004-0097", "CVE-2005-0211");
 
 name["english"] = "Fedora Core 2 2005-105: squid";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-105 (squid).

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects. Unlike traditional
caching software, Squid handles all requests in a single,
non-blocking, I/O-driven process. Squid keeps meta data and especially
hot objects cached in RAM, caches DNS lookups, supports non-blocking
DNS lookups, and implements negative caching of failed requests.

Squid consists of a main server program squid, a Domain Name System
lookup program (dnsserver), a program for retrieving FTP data
(ftpget), and some management and client tools.


* Tue Feb 01 2005 Jay Fenlason 7:2.5.STABLE7-1.FC2.1

- Add more upstream patches, including fixes for
bz#146783 Correct handling of oversized reply headers
bz#146778 CVE-2005-0211 Buffer overflow in WCCP recvfrom() call

* Thu Jan 20 2005 Jay Fenlason 7:2.5.STABLE7-1.FC2

- Upgrade to 2.5.STABLE7 and 18 upstream patches.
- This includes fixes for CVE-2005-0094 CVE-2005-0095 CVE-2004-0096
and CVE-2004-0097. This closes bz#145543 and bz#141938
- This obsoletes Ulrich Drepper's -nonbl patch.
- Add a triggerin on samba-common to make
/var/cache/samba/winbindd_privileged
accessable so that ntlm_auth will work.
This fixes bz#103726

* Mon Oct 18 2004 Jay Fenlason 7:2.5.STABLE6-3

- include patch from Ulrich Drepper to stop
problems with O_NONBLOCK. This closes #136049" );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=356" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.5.STABLE7-1.FC2.1", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-debuginfo-2.5.STABLE7-1.FC2.1", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"squid-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0096", value:TRUE);
 set_kb_item(name:"CVE-2004-0097", value:TRUE);
 set_kb_item(name:"CVE-2005-0211", value:TRUE);
}

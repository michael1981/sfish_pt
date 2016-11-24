#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16113);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0021", "CVE-2005-0022");
 
 name["english"] = "Fedora Core 3 2005-001: exim";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-001 (exim).

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet. In style
it is similar to Smail 3, but its facilities are more extensive, and
in particular it has options for verifying incoming sender and
recipient addresses, for refusing mail from specified hosts, networks,
or senders, and for controlling mail relaying. Exim is in production
use at quite a few sites, some of which move hundreds of thousands of
messages per day.

Exiscan is compiled in to allow inbuilt scanning capability. See
http://duncanthrax.net/exiscan-acl/

Update Information:

This erratum fixes two relatively minor security issues which were
discovered
in Exim in the last few weeks. The Common Vulnerabilities and
Exposures
project (cve.mitre.org) has assigned the names CVE-2005-0021 and
CVE-2005-0022
to these, respectively.

1. The function host_aton() can overflow a buffer if it is presented
with an
illegal IPv6 address that has more than 8 components.

2. The second report described a buffer overflow in the function
spa_base64_to_bits(), which is part of the code for SPA
authentication. This
code originated in the Samba project. The overflow can be exploited
only if
you are using SPA authentication." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=252" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the exim package";
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
if ( rpm_check( reference:"exim-4.43-1.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-mon-4.43-1.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-doc-4.43-1.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-sa-4.43-1.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-debuginfo-4.43-1.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"exim-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0021", value:TRUE);
 set_kb_item(name:"CVE-2005-0022", value:TRUE);
}

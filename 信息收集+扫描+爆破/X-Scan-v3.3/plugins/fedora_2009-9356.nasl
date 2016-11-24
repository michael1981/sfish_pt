
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9356
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40909);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 10 2009-9356: libsilc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9356 (libsilc)");
 script_set_attribute(attribute: "description", value: "SILC Client Library libraries for clients to connect to SILC networks.

SILC (Secure Internet Live Conferencing) is a protocol which provides
secure conferencing services on the Internet over insecure channel.

-
ChangeLog:


Update information :

* Fri Sep  4 2009 Stu Tomlinson <stu nosnilmot com> 1.1.8-7
- Backport patch to fix stack corruption (CVE-2008-7160) (#521256)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-7160");
script_summary(english: "Check for the version of the libsilc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libsilc-1.1.8-7.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

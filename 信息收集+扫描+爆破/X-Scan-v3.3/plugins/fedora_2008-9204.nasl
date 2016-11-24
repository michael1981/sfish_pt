
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9204
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34671);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9204: libtirpc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9204 (libtirpc)");
 script_set_attribute(attribute: "description", value: "This package contains SunLib's implementation of transport-independent
RPC (TI-RPC) documentation.  This library forms a piece of the base of
Open Network Computing (ONC), and is derived directly from the
Solaris 2.3 source.

TI-RPC is an enhanced version of TS-RPC that requires the UNIX System V
Transport Layer Interface (TLI) or an equivalent X/Open Transport Interface
(XTI).  TI-RPC is on-the-wire compatible with the TS-RPC, which is supported
by almost 70 vendors on all major operating systems.  TS-RPC source code
(RPCSRC 4.0) remains available from several internet sites.

-
Update Information:

CVE-2008-4619
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4619");
script_summary(english: "Check for the version of the libtirpc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libtirpc-0.1.7-20.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

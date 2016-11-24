
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10701
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42449);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10701: ocaml-mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10701 (ocaml-mysql)");
 script_set_attribute(attribute: "description", value: "ocaml-mysql is a package for ocaml that provides access to mysql
databases. It consists of low level functions implemented in C and a
module Mysql intended for application development.

-
Update Information:

Patch for CVE 2009-2942 Missing escape function (RHBZ#529321).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2942");
script_summary(english: "Check for the version of the ocaml-mysql package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ocaml-mysql-1.0.4-8.fc11.1", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

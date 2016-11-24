
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2199
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27757);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2199: cacti");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2199 (cacti)");
 script_set_attribute(attribute: "description", value: "Cacti is a complete frontend to RRDTool. It stores all of the
necessary information to create graphs and populate them with
data in a MySQL database. The frontend is completely PHP
driven. Along with being able to maintain graphs, data
sources, and round robin archives in a database, Cacti also
handles the data gathering. There is SNMP support for those
used to creating traffic graphs with MRTG.

-
ChangeLog:


Update information :

* Fri Sep 14 2007 Mike McGrath <mmcgrath redhat com> - 0.8.6j-8
- Fix for CVE-2007-3112 bz#243592
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3112", "CVE-2007-3113");
script_summary(english: "Check for the version of the cacti package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cacti-0.8.6j-8.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

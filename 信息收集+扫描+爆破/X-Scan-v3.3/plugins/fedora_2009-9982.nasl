
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9982
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42283);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-9982: BackupPC");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9982 (BackupPC)");
 script_set_attribute(attribute: "description", value: "BackupPC is a high-performance, enterprise-grade system for backing up Linux
and WinXX PCs and laptops to a server's disk. BackupPC is highly configurable
and easy to install and maintain.

-
ChangeLog:


Update information :

* Fri Sep 25 2009 Johan Cwiklinski <johan AT x-tnd DOT be> 3.1.0-7
- Fix security bug (bug #518412)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3369");
script_summary(english: "Check for the version of the BackupPC package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"BackupPC-3.1.0-7.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

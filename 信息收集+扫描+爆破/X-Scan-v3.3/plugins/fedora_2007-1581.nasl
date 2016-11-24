
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1581
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27722);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1581: qtpfsgui");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1581 (qtpfsgui)");
 script_set_attribute(attribute: "description", value: "Qtpfsgui is a graphical program for assembling bracketed photos into High
Dynamic Range (HDR) images.  It also provides a number of tone-mapping
operators for creating low dynamic range versions of HDR images.

-
ChangeLog:


Update information :

* Sun Aug 12 2007 Douglas E. Warner <silfreed silfreed net> 1.8.12-1
- update to version 1.8.12
- fixes CVE-2007-2956; bug#251674
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2956");
script_summary(english: "Check for the version of the qtpfsgui package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"qtpfsgui-1.8.12-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3283
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36077);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-3283: moodle");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3283 (moodle)");
 script_set_attribute(attribute: "description", value: "Moodle is a course management system (CMS) - a free, Open Source software
package designed using sound pedagogical principles, to help educators create
effective online learning communities.

-
Update Information:

CVE-2009-1171:  The TeX filter in Moodle 1.6 before 1.6.9+, 1.7 before 1.7.7+,
1.8  before 1.8.9, and 1.9 before 1.9.5 allows user-assisted attackers to  read
arbitrary files via an input command in a '$$' sequence, which  causes LaTeX to
include the contents of the file.     Upstream bug and CVS commit:
[9]http://tracker.moodle.org/browse/MDL-18552
[10]http://cvs.moodle.org/moodle/filter/tex/filter.php?r1=1.18.4.4&r2=1.18.4.5
References:
[11]http://www.securityfocus.com/archive/1/archive/1/502231/100/0/threaded
[12]http://www.securityfocus.com/bid/34278  [13]http://www.milw0rm.com/exploits
/8297
Upstream further reported that the above patch is not sufficient and following
change should be used instead:    For >=1.9.0:  [14]http://git.catalyst.net.nz/
gw?p=
moodle-r2.git;a=commitdiff;h=b950f126018a9e16a298d278375a0eedf791e5dd    For
1.6.* - 1.8.*:  [15]http://git.catalyst.net.nz/gw?p=moodle-r2.git;a=commitdiff;
h=cc9
bf1486e7ea9e8cda1e4522b96e07245459a0d
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4796", "CVE-2008-5153", "CVE-2009-0499", "CVE-2009-1171");
script_summary(english: "Check for the version of the moodle package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"moodle-1.9.4-6.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

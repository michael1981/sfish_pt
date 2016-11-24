
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1299
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27709);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-1299: lighttpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1299 (lighttpd)");
 script_set_attribute(attribute: "description", value: "Secure, fast, compliant and very flexible web-server which has been optimized
for high-performance environments. It has a very low memory footprint compared
to other webservers and takes care of cpu-load. Its advanced feature-set
(FastCGI, CGI, Auth, Output-Compression, URL-Rewriting and many more) make
it the perfect webserver-software for every server that is suffering load
problems.

Available rpmbuild rebuild options :
--with : gamin webdavprops webdavlocks memcache
--without : ldap gdbm lua (cml)

-
Update Information:

This security bugfix release fixes a header parsing bug, various mod_auth bugs,
a mod_access bug and a mod_fastcgi local DOS bug.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the lighttpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"lighttpd-1.4.16-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

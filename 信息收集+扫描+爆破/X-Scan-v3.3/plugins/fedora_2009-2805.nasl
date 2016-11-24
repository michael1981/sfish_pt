
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2805
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37197);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-2805: ntop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2805 (ntop)");
 script_set_attribute(attribute: "description", value: "ntop is a network traffic probe that shows the network usage, similar to what
the popular top Unix command does. ntop is based on libpcap and it has been
written in a portable way in order to virtually run on every Unix platform and
on Win32 as well.

ntop users can use a a web browser (e.g. netscape) to navigate through ntop
(that acts as a web server) traffic information and get a dump of the network
status. In the latter case, ntop can be seen as a simple RMON-like agent with
an embedded web interface. The use of:

* a web interface
* limited configuration and administration via the web interface
* reduced CPU and memory usage (they vary according to network size and
traffic)

make ntop easy to use and suitable for monitoring various kind of networks.

ntop should be manually started the first time so that the administrator
password can be selected.

-
Update Information:

ls -lh /var/log/ntop/access.log  -rw-rw-rw- 1 root root 0 2009-02-04 11:53
/var/log/ntop/access.log    Fixed.  log world-writable when the --access-log-
file option is used.    This option is not used in Fedora or Red Hat by default
and is not noted in the configuration file.  It is, however, noted in the ntop
manpage. It would require the root user to add this option to the configuration
in order for this file to be created.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the ntop package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ntop-3.3.8-3.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

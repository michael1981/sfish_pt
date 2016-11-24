
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2788
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31713);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2008-2788: Perlbal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2788 (Perlbal)");
 script_set_attribute(attribute: "description", value: "Perlbal is a single-threaded event-based server supporting HTTP load
balancing, web serving, and a mix of the two. Perlbal can act as either a web
server or a reverse proxy.

One of the defining things about Perlbal is that almost everything can be
configured or reconfigured on the fly without needing to restart the software.
A basic configuration file containing a management port enables you to easily
perform operations on a running instance of Perlbal.

Perlbal can also be extended by means of per-service (and global) plugins that
can override many parts of request handling and behavior.

-
References:

[ 1 ] Bug #439054 - Perlbal crashes upon empty buffered upload attempts
[9]https://bugzilla.redhat.com/show_bug.cgi?id=439054
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the Perlbal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"Perlbal-1.70-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4160
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29272);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-4160: zabbix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4160 (zabbix)");
 script_set_attribute(attribute: "description", value: "ZABBIX is software that monitors numerous parameters of a
network and the health and integrity of servers. ZABBIX
uses a flexible notification mechanism that allows users
to configure e-mail based alerts for virtually any event.
This allows a fast reaction to server problems. ZABBIX
offers excellent reporting and data visualisation features
based on the stored data. This makes ZABBIX ideal for
capacity planning.

ZABBIX supports both polling and trapping. All ZABBIX
reports and statistics, as well as configuration
parameters are accessed through a web-based front end. A
web-based front end ensures that the status of your network
and the health of your servers can be assessed from any
location. Properly configured, ZABBIX can play an important
role in monitoring IT infrastructure. This is equally true
for small organisations with a few servers and for large
companies with a multitude of servers.

-
ChangeLog:


Update information :

* Sat Dec  1 2007 Dan Horak <dan[at]danny.cz> 1.4.2-3
- add security fix (#407181)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the zabbix package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"zabbix-1.4.2-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

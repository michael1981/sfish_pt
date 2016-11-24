
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1737
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31107);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-1737: cacti");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1737 (cacti)");
 script_set_attribute(attribute: "description", value: "Cacti is a complete frontend to RRDTool. It stores all of the
necessary information to create graphs and populate them with
data in a MySQL database. The frontend is completely PHP
driven. Along with being able to maintain graphs, data
sources, and round robin archives in a database, Cacti also
handles the data gathering. There is SNMP support for those
used to creating traffic graphs with MRTG.

-
Update Information:


Update information :

* XSS vulnerabilities   * Path disclosure vulnerabilities   * SQL injection
vulnerabilities   * HTTP response splitting vulnerabilities      bug#0000855:
Unnecessary (and faulty) DEF generation for CF:AVERAGE  bug#0001083: Small
visual fix for Cacti in 'View Cacti Log File'  bug#0001089: Graph xport
modification to increase default rows output  bug#0001091: Poller incorrectly
identifies unique hosts  bug#0001093: CLI Scripts bring MySQL down on large
installations  bug#0001094: Filtering broken on Data Sources page  bug#0001103:
Fix looping poller recache events  bug#0001107: ss_fping.php 100% 'Pkt Loss'
does not work properly  bug#0001114: Graphs with no template and/or no host
cause filtering errors on Graph Management page  bug#0001115: View Poller Cache
does not show Data Sources that have no host  bug#0001118: Graph Generation
fails if e.g. ifDescr contains some blanks  bug#0001132: TCP/UDP ping port
ignored  bug#0001133: Downed Device Detection: None leads to database errors
bug#0001134: update_host_status handles ping_availability incorrectly
bug#0001143: 'U' not allowed as min/max RRD value  bug#0001158: Deleted user
causes error on user log viewer  bug#0001161: Re-assign duplicate radio button
IDs  bug#0001164: Add HTML title attributes for certain pages  bug#0001168:
ALL_DATA_SOURCES_NODUPS includes DUPs? SIMILAR_DATA_SOURCES_DUPS is available
again  bug: Cacti does not guarentee RRA consolidation functions exist in RRA's
bug: Alert on changing logarithmic scaling removed  bug: add_hosts.php did not
accept privacy protocol  security: Fix several security vulnerabilities
feature: show basic RRDtool graph options on Graph Template edit  feature: Add
additional logging to Graph Xport  feature: Add rows dropdown to devices, graph
s
and data sources  feature: Add device_id and event count to devices  feature:
Add ids to devices, graphs and data sources pages  feature: Add database repair
utility
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3112", "CVE-2007-6035");
script_summary(english: "Check for the version of the cacti package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cacti-0.8.7b-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

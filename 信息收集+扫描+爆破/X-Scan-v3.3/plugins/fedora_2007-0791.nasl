
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0791
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27680);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-0791: ekg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0791 (ekg)");
 script_set_attribute(attribute: "description", value: "EKG ('Eksperymentalny Klient Gadu-Gadu') is an open source gadu-gadu
client for UNIX systems. Gadu-Gadu is an instant messaging program,
very popular in Poland.

EKG features include:
- irssi-like ncurses interface
- sending and receiving files
- voice conversations
- launching shell commands on certain events
- reading input from pipe
- python scripting support
- speech synthesis (using an external program)
- encryption support

Please note that the program is not internationalized and all messages
are in Polish (although the commands are in English).

-
Update Information:

Numerous bugfixes (including security), support for the latest GG protocol vers
ion.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1663", "CVE-2007-1664", "CVE-2007-1665");
script_summary(english: "Check for the version of the ekg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ekg-1.7-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

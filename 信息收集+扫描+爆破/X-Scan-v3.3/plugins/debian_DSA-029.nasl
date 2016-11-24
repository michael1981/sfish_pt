# This script was automatically generated from the dsa-029
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14866);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "029");
 script_cve_id("CVE-2001-0136", "CVE-2001-0318");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-029 security update');
 script_set_attribute(attribute: 'description', value:
'The following problems have been reported for the version
of proftpd in Debian 2.2 (potato):

There is a memory leak in the SIZE command which can result in a
denial of service, as reported by Wojciech Purczynski. This is only a
problem if proftpd cannot write to its scoreboard file; the default
configuration of proftpd in Debian is not vulnerable.
A similar memory leak affects the USER command, also as reported by
Wojciech Purczynski. The proftpd in Debian 2.2 is susceptible to this
vulnerability; an attacker can cause the proftpd daemon to crash by
exhausting its available memory.
There were some format string vulnerabilities reported by Przemyslaw
Frasunek. These are not known to have exploits, but have been corrected
as a precaution.

All three of the above vulnerabilities have been corrected in
proftpd-1.2.0pre10-2potato1. We recommend you upgrade your proftpd
package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-029');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-029
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA029] DSA-029-2 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-029-2 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

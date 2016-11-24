# This script was automatically generated from the dsa-1495
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31055);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1495");
 script_cve_id("CVE-2007-5198", "CVE-2007-5623");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1495 security update');
 script_set_attribute(attribute: 'description', value:
'Several local/remote vulnerabilities have been discovered in two of
the plugins for the Nagios network monitoring and management system.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-5198
    A buffer overflow has been discovered in the parser for HTTP
    Location headers (present in the check_http module).
CVE-2007-5623
    A buffer overflow has been discovered in the check_snmp module.
For the old stable distribution (sarge), these problems have been
fixed in version 1.4-6sarge1.
For the stable distribution (etch), these problems have been fixed in
version 1.4.5-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1495');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nagios-plugins package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1495] DSA-1495-1 nagios-plugins");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1495-1 nagios-plugins");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nagios-plugins', release: '3.1', reference: '1.4-6sarge1');
deb_check(prefix: 'nagios-plugins', release: '4.0', reference: '1.4.5-1etch1');
deb_check(prefix: 'nagios-plugins-basic', release: '4.0', reference: '1.4.5-1etch1');
deb_check(prefix: 'nagios-plugins-standard', release: '4.0', reference: '1.4.5-1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

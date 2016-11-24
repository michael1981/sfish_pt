# This script was automatically generated from the dsa-1250
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24247);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1250");
 script_cve_id("CVE-2006-6799");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1250 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that cacti, a frontend to rrdtool, performs insufficient
validation of data passed to the <q>cmd</q> script, which allows SQL
injection and the execution of arbitrary shell commands.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.6c-7sarge4.
For the upcoming stable distribution (etch) this problem has been
fixed in version 0.8.6i-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1250');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cacti package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1250] DSA-1250-1 cacti");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1250-1 cacti");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cacti', release: '3.1', reference: '0.8.6c-7sarge4');
deb_check(prefix: 'cacti', release: '4.0', reference: '0.8.6i-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

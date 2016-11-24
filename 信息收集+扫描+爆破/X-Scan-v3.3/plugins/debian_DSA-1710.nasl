# This script was automatically generated from the dsa-1710
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35461);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1710");
 script_cve_id("CVE-2009-0241");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1710 security update');
 script_set_attribute(attribute: 'description', value:
'Spike Spiegel discovered a stack-based buffer overflow in gmetad, the
meta-daemon for the ganglia cluster monitoring toolkit, which could be
triggered via a request with long path names and might enable
arbitrary code execution.
For the stable distribution (etch), this problem has been fixed in
version 2.5.7-3.1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1710');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ganglia-monitor-core packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1710] DSA-1710-1 ganglia-monitor-core");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1710-1 ganglia-monitor-core");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ganglia-monitor', release: '4.0', reference: '2.5.7-3.1etch1');
deb_check(prefix: 'gmetad', release: '4.0', reference: '2.5.7-3.1etch1');
deb_check(prefix: 'libganglia1', release: '4.0', reference: '2.5.7-3.1etch1');
deb_check(prefix: 'libganglia1-dev', release: '4.0', reference: '2.5.7-3.1etch1');
deb_check(prefix: 'ganglia-monitor-core', release: '4.0', reference: '2.5.7-3.1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

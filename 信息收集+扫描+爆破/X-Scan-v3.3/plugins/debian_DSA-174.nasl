# This script was automatically generated from the dsa-174
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15011);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "174");
 script_cve_id("CVE-2002-1215");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-174 security update');
 script_set_attribute(attribute: 'description', value:
'Nathan Wallwork discovered a buffer overflow in heartbeat, a subsystem
for High-Availability Linux.  A remote attacker could send a specially
crafted UDP packet that overflows a buffer, leaving heartbeat to
execute arbitrary code as root.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-174');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heartbeat package immediately if
you run internet connected servers that are heartbeat-monitored.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA174] DSA-174-1 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-174-1 heartbeat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heartbeat', release: '3.0', reference: '0.4.9.0l-7.2');
deb_check(prefix: 'ldirectord', release: '3.0', reference: '0.4.9.0l-7.2');
deb_check(prefix: 'libstonith-dev', release: '3.0', reference: '0.4.9.0l-7.2');
deb_check(prefix: 'libstonith0', release: '3.0', reference: '0.4.9.0l-7.2');
deb_check(prefix: 'stonith', release: '3.0', reference: '0.4.9.0l-7.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

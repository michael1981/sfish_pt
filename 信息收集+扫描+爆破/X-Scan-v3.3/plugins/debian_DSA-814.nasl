# This script was automatically generated from the dsa-814
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19710);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "814");
 script_cve_id("CVE-2005-2672");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-814 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña discovered that a script of lm-sensors,
utilities to read temperature/voltage/fan sensors, creates a temporary
file with a predictable filename, leaving it vulnerable for a symlink
attack.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.9.1-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-814');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lm-sensors package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA814] DSA-814-1 lm-sensors");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-814-1 lm-sensors");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-patch-2.4-lm-sensors', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'libsensors-dev', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'libsensors3', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-386', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-586tsc', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-686', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-686-smp', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-k6', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-k7', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-2.4.27-2-k7-smp', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'lm-sensors-source', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'sensord', release: '3.1', reference: '2.9.1-1sarge2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-1755
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36040);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1755");
 script_cve_id("CVE-2009-0784");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1755 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjoelund discovered that a race condition in the stap tool shipped
by Systemtap, an instrumentation system for Linux 2.6, allows local
privilege escalation for members of the stapusr group.
The old stable distribution (etch) isn\'t affected.
For the stable distribution (lenny), this problem has been fixed in
version 0.0.20080705-1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1755');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your systemtap package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1755] DSA-1755-1 systemtap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1755-1 systemtap");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'systemtap', release: '5.0', reference: '0.0.20080705-1+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

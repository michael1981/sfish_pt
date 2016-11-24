# This script was automatically generated from the dsa-186
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15023);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "186");
 script_cve_id("CVE-2002-1251");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-186 security update');
 script_set_attribute(attribute: 'description', value:
'Enrico Zini discovered a buffer overflow in log2mail, a daemon for
watching logfiles and sending lines with matching patterns via mail.
The log2mail daemon is started upon system boot and runs as root.  A
specially crafted (remote) log message could overflow a static buffer,
potentially leaving log2mail to execute arbitrary code as root.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-186');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your log2mail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA186] DSA-186-1 log2mail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-186-1 log2mail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'log2mail', release: '3.0', reference: '0.2.5.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

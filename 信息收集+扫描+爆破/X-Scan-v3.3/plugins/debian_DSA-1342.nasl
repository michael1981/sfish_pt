# This script was automatically generated from the dsa-1342
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25825);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1342");
 script_cve_id("CVE-2007-3103");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1342 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that a race condition in the init.d script of the X Font
Server allows the modification of file permissions of arbitrary files if
the local administrator can be tricked into restarting the X font server.
For the oldstable distribution (sarge) xfs is present as part of the
monolithic xfree86 package. A fix will be provided along with a future
security update.
For the stable distribution (etch) this problem has been fixed in
version 1.0.1-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1342');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xfs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1342] DSA-1342-1 xfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1342-1 xfs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xfs', release: '4.0', reference: '1.0.1-6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

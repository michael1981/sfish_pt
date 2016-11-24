# This script was automatically generated from the dsa-1262
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24765);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1262");
 script_cve_id("CVE-2007-1007");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1262 security update');
 script_set_attribute(attribute: 'description', value:
'<q>Mu Security</q> discovered that a format string vulnerability in
the VoIP solution GnomeMeeting allows the execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.1-1sarge1.
For the upcoming stable distribution (etch) this problem has been
fixed in version 2.0.3-2.1 of the ekiga package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1262');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnomemeeting package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1262] DSA-1262-1 gnomemeeting");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1262-1 gnomemeeting");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnomemeeting', release: '3.1', reference: '1.2.1-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

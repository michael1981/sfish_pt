# This script was automatically generated from the dsa-1705
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35382);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1705");
 script_cve_id("CVE-2008-5718");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1705 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that netatalk, an implementation of the AppleTalk
suite, is affected by a command injection vulnerability when processing
PostScript streams via papd.  This could lead to the execution of
arbitrary code.  Please note that this only affects installations that are
configured to use a pipe command in combination with wildcard symbols
substituted with values of the printed job.
For the stable distribution (etch) this problem has been fixed in
version 2.0.3-4+etch1.
For the upcoming stable distribution (lenny) this problem has been fixed
in version 2.0.3-11+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1705');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netatalk package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1705] DSA-1705-1 netatalk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1705-1 netatalk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'netatalk', release: '4.0', reference: '2.0.3-4+etch1');
deb_check(prefix: 'netatalk', release: '5.0', reference: '2.0.3-11+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

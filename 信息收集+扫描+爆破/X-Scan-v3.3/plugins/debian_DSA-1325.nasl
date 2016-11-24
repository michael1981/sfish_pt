# This script was automatically generated from the dsa-1325
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25675);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1325");
 script_cve_id("CVE-2007-1002", "CVE-2007-3257");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1325 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Evolution, a
groupware suite with mail client and organizer. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2007-1002
    Ulf Härnhammar discovered that a format string vulnerability in
    the handling of shared calendars may allow the execution of arbitrary
    code.
CVE-2007-3257
    It was discovered that the IMAP code in the Evolution Data Server
    performs insufficient sanitising of a value later used an array index,
    which can lead to the execution of arbitrary code.
For the oldstable distribution (sarge) these problems have been fixed in
version 2.0.4-2sarge2. Packages for hppa, mips and powerpc are not yet
available. They will be provided later.
For the stable distribution (etch) these problems have been fixed
in version 2.6.3-6etch1. Packages for mips are not yet available. They
will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1325');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your evolution packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1325] DSA-1325-1 evolution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1325-1 evolution");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.4-2sarge2');
deb_check(prefix: 'evolution-dev', release: '3.1', reference: '2.0.4-2sarge2');
deb_check(prefix: 'evolution', release: '4.0', reference: '2.6.3-6etch1');
deb_check(prefix: 'evolution-common', release: '4.0', reference: '2.6.3-6etch1');
deb_check(prefix: 'evolution-dbg', release: '4.0', reference: '2.6.3-6etch1');
deb_check(prefix: 'evolution-dev', release: '4.0', reference: '2.6.3-6etch1');
deb_check(prefix: 'evolution-plugins', release: '4.0', reference: '2.6.3-6etch1');
deb_check(prefix: 'evolution-plugins-experimental', release: '4.0', reference: '2.6.3-6etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

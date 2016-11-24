# This script was automatically generated from the dsa-1718
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35622);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1718");
 script_cve_id("CVE-2009-0126");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1718 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the core client for the BOINC distributed
computing infrastructure performs incorrect validation of the return
values of OpenSSL\'s RSA functions.
For the stable distribution (etch), this problem has been fixed in
version 5.4.11-4+etch1.
For the upcoming stable distribution (lenny), this problem has been
fixed in version 6.2.14-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1718');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your boinc packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1718] DSA-1718-1 boinc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1718-1 boinc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'boinc-client', release: '4.0', reference: '5.4.11-4+etch1');
deb_check(prefix: 'boinc-dev', release: '4.0', reference: '5.4.11-4+etch1');
deb_check(prefix: 'boinc-manager', release: '4.0', reference: '5.4.11-4+etch1');
deb_check(prefix: 'boinc', release: '4.0', reference: '5.4.11-4+etch1');
deb_check(prefix: 'boinc', release: '5.0', reference: '6.2.14-3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

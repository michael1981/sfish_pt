# This script was automatically generated from the dsa-1236
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23849);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1236");
 script_cve_id("CVE-2006-5875");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1236 security update');
 script_set_attribute(attribute: 'description', value:
'Antti-Juhani Kaijanaho discovered that enemies-of-carlotta, a simple
manager for mailing lists, does not properly sanitise email addresses
before passing them through to the system shell.
For the stable distribution (sarge), this problem has been fixed in version 
1.0.3-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1236');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your enemies-of-carlotta package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1236] DSA-1236-1 enemies-of-carlotta");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1236-1 enemies-of-carlotta");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'enemies-of-carlotta', release: '3.1', reference: '1.0.3-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

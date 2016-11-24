# This script was automatically generated from the dsa-1477
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30112);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1477");
 script_cve_id("CVE-2007-5837");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1477 security update');
 script_set_attribute(attribute: 'description', value:
'Duncan Gilmore discovered that yarssr, an RSS aggregator and reader,
performs insufficient input sanitising, which could result in the
execution of arbitrary shell commands if a malformed feed is read.
Due to a technical limitation of the archive management scripts, the
fix for the old stable distribution (sarge) needs to be postponed
by a few days.
For the stable distribution (etch), this problem has been fixed in
version 0.2.2-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1477');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your yarssr packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1477] DSA-1477-1 yarssr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1477-1 yarssr");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'yarssr', release: '4.0', reference: '0.2.2-1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-355
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15192);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "355");
 script_cve_id("CVE-2003-0614");
 script_bugtraq_id(8288);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-355 security update');
 script_set_attribute(attribute: 'description', value:
'Larry Nguyen discovered a cross site scripting vulnerability in gallery,
a web-based photo album written in php.  This security flaw can allow a
malicious user to craft a URL that executes Javascript code on your
website.
For the current stable distribution (woody) this problem has been fixed
in version 1.25-8woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-355');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-355
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA355] DSA-355-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-355-1 gallery");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody1');
deb_check(prefix: 'gallery', release: '3.0', reference: '1.25-8woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

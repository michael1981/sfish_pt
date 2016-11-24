# This script was automatically generated from the dsa-558
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15656);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "558");
 script_cve_id("CVE-2004-0809");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-558 security update');
 script_set_attribute(attribute: 'description', value:
'Julian Reschke reported a problem in mod_dav of Apache 2 in connection
with a NULL pointer dereference.  When running in a threaded model,
especially with Apache 2, a segmentation fault can take out a whole
process and hence create a denial of service for the whole server.
For the stable distribution (woody) this problem has been fixed in
version 1.0.3-3.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-558');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mod_dav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA558] DSA-558-1 libapache-mod-dav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-558-1 libapache-mod-dav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-dav', release: '3.0', reference: '1.0.3-3.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

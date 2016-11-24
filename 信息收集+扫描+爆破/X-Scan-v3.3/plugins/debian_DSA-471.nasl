# This script was automatically generated from the dsa-471
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15308);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "471");
 script_cve_id("CVE-2004-0374");
 script_bugtraq_id(10005);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-471 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered recently in Interchange, an e-commerce
and general HTTP database display system.  This vulnerability can be
exploited by an attacker to expose the content of arbitrary variables.
An attacker may learn SQL access information for your Interchange
application and use this information to read and manipulate sensitive
data.
For the stable distribution (woody) this problem has been fixed in
version 4.8.3.20020306-1.woody.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-471');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your interchange package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA471] DSA-471-1 interchange");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-471-1 interchange");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.2');
deb_check(prefix: 'interchange-cat-foundation', release: '3.0', reference: '4.8.3.20020306-1.woody.2');
deb_check(prefix: 'interchange-ui', release: '3.0', reference: '4.8.3.20020306-1.woody.2');
deb_check(prefix: 'libapache-mod-interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

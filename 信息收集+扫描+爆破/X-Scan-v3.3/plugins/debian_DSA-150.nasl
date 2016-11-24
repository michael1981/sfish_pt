# This script was automatically generated from the dsa-150
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14987);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "150");
 script_cve_id("CVE-2002-0874");
 script_bugtraq_id(5453);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-150 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in Interchange, an e-commerce and
general HTTP database display system, which can lead to an attacker
being able to read any file to which the user of the Interchange
daemon has sufficient permissions, when Interchange runs in "INET
mode" (internet domain socket).  This is not the default setting in
Debian packages, but configurable with Debconf and via configuration
file.  We also believe that this bug cannot exploited on a regular
Debian system.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-150');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your interchange packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA150] DSA-150-1 interchange");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-150-1 interchange");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.1');
deb_check(prefix: 'interchange-cat-foundation', release: '3.0', reference: '4.8.3.20020306-1.woody.1');
deb_check(prefix: 'interchange-ui', release: '3.0', reference: '4.8.3.20020306-1.woody.1');
deb_check(prefix: 'libapache-mod-interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

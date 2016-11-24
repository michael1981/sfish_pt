# This script was automatically generated from the dsa-528
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15365);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "528");
 script_cve_id("CVE-2004-0635");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-528 security update');
 script_set_attribute(attribute: 'description', value:
'Several denial of service vulnerabilities were discovered in ethereal,
a network traffic analyzer.  These vulnerabilities are described in the
ethereal advisory "enpa-sa-00015".  Of these, only one (CVE-2004-0635)
affects the version of ethereal in Debian woody.  This vulnerability
could be exploited by a remote attacker to crash ethereal with an
invalid SNMP packet.
For the current stable distribution (woody), these problems have been
fixed in version 0.9.4-1woody8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-528');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-528
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA528] DSA-528-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-528-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody8');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody8');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody8');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody8');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

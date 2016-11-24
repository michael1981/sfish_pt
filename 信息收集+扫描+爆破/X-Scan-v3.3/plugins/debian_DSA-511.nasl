# This script was automatically generated from the dsa-511
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15348);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "511");
 script_cve_id("CVE-2004-0176");
 script_bugtraq_id(9952);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-511 security update');
 script_set_attribute(attribute: 'description', value:
'Several buffer overflow vulnerabilities were discovered in ethereal, a
network traffic analyzer.  These vulnerabilities are described in the
ethereal advisory "enpa-sa-00013".  Of these, only some parts of
CVE-2004-0176 affect the version of ethereal in Debian woody.
CVE-2004-0367 and CVE-2004-0365 are not applicable to this version.
For the current stable distribution (woody), these problems have been
fixed in version 0.9.4-1woody7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-511');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-511
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA511] DSA-511-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-511-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody7');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody7');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody7');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

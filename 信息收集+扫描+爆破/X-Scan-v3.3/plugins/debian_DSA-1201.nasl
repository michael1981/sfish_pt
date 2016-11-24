# This script was automatically generated from the dsa-1201
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22931);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1201");
 script_cve_id("CVE-2006-4574", "CVE-2006-4805");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1201 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Ethereal network
scanner. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2005-4574
    It was discovered that the MIME multipart dissector is vulnerable to
    denial of service caused by an off-by-one overflow.
CVE-2006-4805
    It was discovered that the XOT dissector is vulnerable to denial
    of service caused by memory corruption.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge9. Due to technical problems with the security
buildd infrastructure this update lacks builds for the hppa and sparc
architecture. They will be released as soon as the problems are resolved.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1201');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1201] DSA-1201-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1201-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge9');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge9');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge9');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

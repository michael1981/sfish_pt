# This script was automatically generated from the dsa-1127
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22669);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1127");
 script_cve_id("CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1127 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Ethereal network
sniffer, which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2006-3628
    Ilja van Sprundel discovered that the FW-1 and MQ dissectors are
    vulnerable to format string attacks.
CVE-2006-3629
    Ilja van Sprundel discovered that the MOUNT dissector is vulnerable
    to denial of service through memory exhaustion.
CVE-2006-3630
    Ilja van Sprundel discovered off-by-one overflows in the NCP NMAS and
    NDPS dissectors.
CVE-2006-3631
    Ilja van Sprundel discovered a buffer overflow in the NFS dissector.
CVE-2006-3632
    Ilja van Sprundel discovered that the SSH dissector is vulnerable
    to denial of service through an infinite loop.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1127');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1127] DSA-1127-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1127-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge6');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge6');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge6');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

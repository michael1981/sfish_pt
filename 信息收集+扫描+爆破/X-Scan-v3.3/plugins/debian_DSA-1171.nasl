# This script was automatically generated from the dsa-1171
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22713);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1171");
 script_cve_id("CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3246", "CVE-2005-3248", "CVE-2006-4333");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1171 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Ethereal network
scanner, which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2006-4333
    It was discovered that the Q.2391 dissector is vulnerable to denial
    of service caused by memory exhaustion.
CVE-2005-3241
    It was discovered that the FC-FCS, RSVP and ISIS-LSP dissectors are
    vulnerable to denial of service caused by memory exhaustion.
CVE-2005-3242
    It was discovered that the IrDA and SMB dissectors are vulnerable to
    denial of service caused by memory corruption.
CVE-2005-3243
    It was discovered that the SLIMP3 and AgentX dissectors are vulnerable
    to code injection caused by buffer overflows.
CVE-2005-3244
    It was discovered that the BER dissector is vulnerable to denial of
    service caused by an infinite loop.
CVE-2005-3246
    It was discovered that the NCP and RTnet dissectors are vulnerable to
    denial of service caused by a null pointer dereference.
CVE-2005-3248
    It was discovered that the X11 dissector is vulnerable to denial of service
    caused by a division through zero.
This update also fixes a 64 bit-specific regression in the ASN.1 decoder, which
was introduced in a previous DSA.
For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1171');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1171] DSA-1171-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1171-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge8');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge8');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge8');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

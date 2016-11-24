# This script was automatically generated from the dsa-1135
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22677);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1135");
 script_cve_id("CVE-2006-3600");
 script_bugtraq_id(18961);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1135 security update');
 script_set_attribute(attribute: 'description', value:
'Kevin Kofler discovered several stack-based buffer overflows in the
LookupTRM::lookup function in libtunepimp, a MusicBrainz tagging
library, which allows remote attackers to cause a denial of service or
execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 0.3.0-3sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1135');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtunepimp packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1135] DSA-1135-1 libtunepimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1135-1 libtunepimp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtunepimp-bin', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'libtunepimp-perl', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'libtunepimp2', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'libtunepimp2-dev', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'python-tunepimp', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'python2.2-tunepimp', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'python2.3-tunepimp', release: '3.1', reference: '0.3.0-3sarge2');
deb_check(prefix: 'libtunepimp', release: '3.1', reference: '0.3.0-3sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

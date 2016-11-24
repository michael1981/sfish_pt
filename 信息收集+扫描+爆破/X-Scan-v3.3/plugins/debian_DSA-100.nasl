# This script was automatically generated from the dsa-100
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14937);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "100");
 script_cve_id("CVE-2001-1228");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-100 security update');
 script_set_attribute(attribute: 'description', value:
'GOBBLES found a buffer overflow in gzip that occurs when compressing
files with really long filenames.  Even though GOBBLES claims to have
developed an exploit to take advantage of this bug, it has been said
by others that this problem is not likely to be exploitable as other
security incidents.
Additionally, the Debian version of gzip from the stable release does
not segfault, and hence does not directly inherit this problem.
However, better be safe than sorry, so we have prepared an update for
you.
Please make sure you are running an up-to-date version from
stable/unstable/testing with at least version 1.2.4-33.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-100');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-100
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA100] DSA-100-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-100-1 gzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gzip', release: '2.2', reference: '1.2.4-33.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-015
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14852);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "015");
 script_cve_id("CVE-2001-0195");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-015 security update');
 script_set_attribute(attribute: 'description', value:
'Versions of the sash package prior to 3.4-4 did not clone
/etc/shadow properly, causing it to be made world-readable.

This package only exists in stable, so if you are running unstable you won\'t
see a bugfix unless you use the resources from the bottom of this message to
the proper configuration.

We recommend you upgrade your sash package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-015');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-015
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA015] DSA-015-1 sash");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-015-1 sash");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sash', release: '2.2', reference: '3.4-6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

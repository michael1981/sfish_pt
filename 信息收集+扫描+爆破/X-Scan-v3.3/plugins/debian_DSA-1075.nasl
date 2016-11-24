# This script was automatically generated from the dsa-1075
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22617);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1075");
 script_cve_id("CVE-2006-2644");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1075 security update');
 script_set_attribute(attribute: 'description', value:
'Hendrik Weimer discovered that awstats can execute arbitrary commands
under the user id the web-server runs when users are allowed to supply
arbitrary configuration files.  Even though, this bug was referenced
in DSA 1058 accidentally, it was not fixed yet.
The new default behaviour is not to accept arbitrary configuration
directories from the user.  This can be overwritten by the
AWSTATS_ENABLE_CONFIG_DIR environment variable when users are to be
trusted.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.4-1sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1075');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your awstats package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1075] DSA-1075-1 awstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1075-1 awstats");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

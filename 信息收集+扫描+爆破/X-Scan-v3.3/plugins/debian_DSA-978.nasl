# This script was automatically generated from the dsa-978
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(22844);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "978");
 script_cve_id("CVE-2006-0455");

 script_set_attribute(attribute: "synopsis", value: 
'The remote host is missing the DSA-978 security update.');
 script_set_attribute(attribute: "description", value: 
'Tavis Ormandy noticed that gnupg, the GNU privacy guard - a free PGP
replacement, verifies external signatures of files successfully even
though they don\'t contain a signature at all.
For the old stable distribution (woody) this problem has been fixed in
version 1.0.6-4woody4.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your gnupg package.
Please note that this security advisory has been superseeded by
DSA 993. Therefore, the updated packages are no longer available from 
this page.');
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2006/dsa-978");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2006/dsa-978
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();

 script_copyright(english: "This script is (C) 2007-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA978] DSA-978-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-978-1 gnupg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian sarge.\nUpgrade to gnupg_1.4.1-1sarge1\n');
}
if (deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian woody.\nUpgrade to gnupg_1.0.6-4woody4\n');
}
if (w) { security_warning(port: 0, extra: desc); }

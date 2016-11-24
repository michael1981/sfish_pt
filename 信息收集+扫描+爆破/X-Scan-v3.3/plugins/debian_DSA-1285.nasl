# This script was automatically generated from the dsa-1285
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25152);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1285");
 script_cve_id("CVE-2007-1622", "CVE-2007-1893", "CVE-2007-1894", "CVE-2007-1897");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1285 security update');
 script_set_attribute(attribute: 'description', value:
'CVE-2007-1622
    Cross-site scripting (XSS) vulnerability in wp-admin/vars.php in
    WordPress before 2.0.10 RC2, and before 2.1.3 RC2 in the 2.1 series,
    allows remote authenticated users with theme privileges to inject
    arbitrary web script or HTML via the PATH_INFO in the administration
    interface, related to loose regular expression processing of PHP_SELF.
CVE-2007-1893
    WordPress 2.1.2, and probably earlier, allows remote authenticated
    users with the contributor role to bypass intended access restrictions
    and invoke the publish_posts functionality, which can be used to
    <q>publish a previously saved post.</q>
CVE-2007-1894
    Cross-site scripting (XSS) vulnerability in
    wp-includes/general-template.php in WordPress before 20070309 allows
    remote attackers to inject arbitrary web script or HTML via the year
    parameter in the wp_title function.
CVE-2007-1897
    SQL injection vulnerability in xmlrpc.php in WordPress 2.1.2, and
    probably earlier, allows remote authenticated users to execute
    arbitrary SQL commands via a string parameter value in an XML RPC
    mt.setPostCategories method call, related to the post_id variable.
For the stable distribution (etch) these issues have been fixed in
version 2.0.10-1.
For the testing and unstable distributions (lenny and sid,
respectively), these issues have been fixed in version 2.1.3-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1285');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wordpress package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1285] DSA-1285-1 wordpress");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1285-1 wordpress");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wordpress', release: '4.0', reference: '2.0.10-1');
deb_check(prefix: 'wordpress', release: '5.0', reference: '2.1.3-1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

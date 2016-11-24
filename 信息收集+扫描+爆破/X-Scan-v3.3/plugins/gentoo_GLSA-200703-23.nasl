# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(24889);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-23");
 script_cve_id("CVE-2007-1049", "CVE-2007-1230", "CVE-2007-1244", "CVE-2007-1409");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-23
(WordPress: Multiple vulnerabilities)


    WordPress contains cross-site scripting or cross-site scripting forgery
    vulnerabilities reported by:
    g30rg3_x in the "year"
    parameter of the wp_title() function
    Alexander Concha in the
    "demo" parameter of wp-admin/admin.php
    Samenspender and Stefan
    Friedli in the "post" parameter of wp-admin/post.php and
    wp-admin/page.php, in the "cat_ID" parameter of wp-admin/categories.php
    and in the "c" parameter of wp-admin/comment.php
    PsychoGun in
    the "file" parameter of wp-admin/templates.php
    Additionally, WordPress prints the full PHP script paths in some error
    messages.
  
Impact

    The cross-site scripting vulnerabilities can be triggered to steal
    browser session data or cookies. A remote attacker can entice a user to
    browse to a specially crafted web page that can trigger the cross-site
    request forgery vulnerability and perform arbitrary WordPress actions
    with the permissions of the user. Additionally, the path disclosure
    vulnerability could help an attacker to perform other attacks.
  
Workaround

    There is no known workaround at this time for all these
    vulnerabilities.
  
');
script_set_attribute(attribute:'solution', value: '
    Due to the numerous recently discovered vulnerabilities in WordPress,
    this package has been masked in the portage tree. All WordPress users
    are advised to unmerge it.
    # emerge --unmerge "www-apps/wordpress"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1049');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1230');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1244');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1409');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/24430/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-23] WordPress: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list(), vulnerable: make_list("le 2.1.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

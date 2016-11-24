# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-10.xml
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
 script_id(23675);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-10");
 script_cve_id("CVE-2006-5705");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-10
(WordPress: Multiple vulnerabilities)


    "random" discovered that users can enter serialized objects as strings
    in their profiles that will be harmful when unserialized. "adapter"
    found out that user-edit.php fails to effectively deny non-permitted
    users access to other user\'s metadata. Additionally, a directory
    traversal vulnerability in the wp-db-backup module was discovered.
  
Impact

    By entering specially crafted strings in his profile, an attacker can
    crash PHP or even the web server running WordPress. Additionally, by
    crafting a simple URL, an attacker can read metadata of any other user,
    regardless of their own permissions. A user with the permission to use
    the database backup plugin can possibly overwrite files he otherwise
    has no access to.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-2.0.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5705');
script_set_attribute(attribute: 'see_also', value: 'http://trac.wordpress.org/ticket/3142');
script_set_attribute(attribute: 'see_also', value: 'http://trac.wordpress.org/ticket/2591');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-10] WordPress: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 2.0.5"), vulnerable: make_list("lt 2.0.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

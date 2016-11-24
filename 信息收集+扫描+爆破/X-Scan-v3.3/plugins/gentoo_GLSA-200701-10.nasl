# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-10.xml
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
 script_id(24208);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200701-10");
 script_cve_id("CVE-2006-6808", "CVE-2007-0107", "CVE-2007-0109");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-10
(WordPress: Multiple vulnerabilities)


    When decoding trackbacks with alternate character sets, WordPress does
    not correctly sanitize the entries before further modifying a SQL
    query. WordPress also displays different error messages in wp-login.php
    based upon whether or not a user exists. David Kierznowski has
    discovered that WordPress fails to properly sanitize recent file
    information in /wp-admin/templates.php before sending that information
    to a browser.
  
Impact

    An attacker could inject arbitrary SQL into WordPress database queries.
    An attacker could also determine if a WordPress user existed by trying
    to login as that user, better facilitating brute force attacks. Lastly,
    an attacker authenticated to view the administrative section of a
    WordPress instance could try to edit a file with a malicious filename;
    this may cause arbitrary HTML or JavaScript to be executed in users\'
    browsers viewing /wp-admin/templates.php.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-2.0.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6808');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0109');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-10] WordPress: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 2.0.6"), vulnerable: make_list("lt 2.0.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

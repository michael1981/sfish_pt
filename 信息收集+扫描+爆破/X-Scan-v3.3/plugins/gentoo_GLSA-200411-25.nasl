# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-25.xml
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
 script_id(15736);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-25");
 script_cve_id("CVE-2004-1036");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-25
(SquirrelMail: Encoded text XSS vulnerability)


    SquirrelMail fails to properly sanitize certain strings when decoding
    specially-crafted headers.
  
Impact

    By enticing a user to read a specially-crafted e-mail, an attacker can
    execute arbitrary scripts running in the context of the victim\'s
    browser. This could lead to a compromise of the user\'s webmail account,
    cookie theft, etc.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.3a-r2"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://article.gmane.org/gmane.mail.squirrelmail.user/21169');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1036');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-25] SquirrelMail: Encoded text XSS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail: Encoded text XSS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.3a-r2"), vulnerable: make_list("lt 1.4.3a-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

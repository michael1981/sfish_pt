# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-39.xml
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
 script_id(16430);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-39");
 script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-39 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-39
(SquirrelMail: Multiple vulnerabilities)


    SquirrelMail fails to properly sanitize certain strings when
    decoding specially-crafted strings, which can lead to PHP file
    inclusion and XSS.
    Insufficient checking of incoming URLs
    in prefs.php (CAN-2005-0075) and in webmail.php (CAN-2005-0103).
    Insufficient escaping of integers in webmail.php
    (CAN-2005-0104).
  
Impact

    By sending a specially-crafted URL, an attacker can execute
    arbitrary code from the local system with the permissions of the web
    server. Furthermore by enticing a user to load a specially-crafted URL,
    it is possible to display arbitrary remote web pages in Squirrelmail\'s
    frameset and execute arbitrary scripts running in the context of the
    victim\'s browser. This could lead to a compromise of the user\'s webmail
    account, cookie theft, etc.
  
Workaround

    The arbitrary code execution is only possible with
    "register_globals" set to "On". Gentoo ships PHP with
    "register_globals" set to "Off" by default. There are no known
    workarounds for the other issues at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.4"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/mailarchive/message.php?msg_id=10628451');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0075');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0103');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0104');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-39.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-39] SquirrelMail: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.4"), vulnerable: make_list("le 1.4.3a-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

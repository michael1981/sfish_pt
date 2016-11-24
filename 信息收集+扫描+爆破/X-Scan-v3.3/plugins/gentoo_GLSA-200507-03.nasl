# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-03.xml
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
 script_id(18607);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200507-03");
 script_cve_id("CVE-2005-2086");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-03
(phpBB: Arbitrary command execution)


    Ron van Daal discovered that phpBB contains a vulnerability in the
    highlighting code.
  
Impact

    Successful exploitation would grant an attacker unrestricted access to
    the PHP exec() or system() functions, allowing the execution of
    arbitrary commands with the rights of the web server.
  
Workaround

    Please follow the instructions given in the phpBB announcement.
  
');
script_set_attribute(attribute:'solution', value: '
    The phpBB package is no longer supported by Gentoo Linux and has been
    masked in the Portage repository, no further announcements will be
    issued regarding phpBB updates. Users who wish to continue using phpBB
    are advised to monitor and refer to www.phpbb.com for more information.
    To continue using the Gentoo-provided phpBB package, please refer to
    the Portage documentation on unmasking packages and upgrade to 2.0.16.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2086');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=302011');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-03] phpBB: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpBB", unaffected: make_list("ge 2.0.16"), vulnerable: make_list("lt 2.0.16")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

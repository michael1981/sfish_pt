# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-07.xml
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
 script_id(14493);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-07");
 script_cve_id("CVE-2004-0400");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-07
(Exim verify=header_syntax buffer overflow)


    When the option "verify = header_syntax" is used in an ACL in the
    configuration file, Exim is vulnerable to a buffer overflow attack that can
    be triggered remotely by sending malicious headers in an email message.
    Note that this option is not enabled in Exim\'s default configuration file.
  
Impact

    This vulnerability can be exploited to trigger a denial of service attack
    and potentially execute arbitrary code with the rights of the user used by
    the Exim daemon (by default this is the "mail" user in Gentoo Linux).
  
Workaround

    Make sure the verify=header_syntax option is not used in your exim.conf
    file.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of Exim should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=mail-mta/exim-4.33-r1"
    # emerge ">=mail-mta/exim-4.33-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0400');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-07] Exim verify=header_syntax buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Exim verify=header_syntax buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/exim", unaffected: make_list("ge 4.33-r1"), vulnerable: make_list("le 4.33")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

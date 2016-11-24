# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-12.xml
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
 script_id(33558);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200807-12");
 script_cve_id("CVE-2007-4584", "CVE-2007-5839");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-12
(BitchX: Multiple vulnerabilities)


    bannedit reported a boundary error when handling overly long IRC MODE
    messages (CVE-2007-4584). Nico Golde reported an insecure creation of a
    temporary file within the e_hostname() function (CVE-2007-5839).
  
Impact

    A remote attacker could entice a user to connect to a malicious IRC
    server, resulting in the remote execution of arbitrary code with the
    privileges of the user running the application. A local attacker could
    perform symlink attacks to overwrite arbitrary files on the local
    machine.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Since BitchX is no longer maintained, we recommend that users unmerge
    the vulnerable package and switch to another IRC client:
    # emerge --unmerge "net-irc/bitchx"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4584');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5839');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-12] BitchX: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BitchX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/bitchx", unaffected: make_list(), vulnerable: make_list("le 1.1-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

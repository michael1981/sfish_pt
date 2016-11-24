# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-32.xml
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
 script_id(17235);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-32");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-32 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-32
(UnAce: Buffer overflow and directory traversal vulnerabilities)


    Ulf Harnhammar discovered that UnAce suffers from buffer overflows
    when testing, unpacking or listing specially crafted ACE archives
    (CAN-2005-0160). He also found out that UnAce is vulnerable to
    directory traversal attacks, if an archive contains "./.." sequences or
    absolute filenames (CAN-2005-0161).
  
Impact

    An attacker could exploit the buffer overflows to execute
    malicious code or the directory traversals to overwrite arbitrary
    files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All UnAce users should upgrade to the latest available 1.2
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/unace-1.2b-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0160');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0161');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-32.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-32] UnAce: Buffer overflow and directory traversal vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UnAce: Buffer overflow and directory traversal vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/unace", unaffected: make_list("rge 1.2b-r1"), vulnerable: make_list("le 1.2b", "ge 2.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

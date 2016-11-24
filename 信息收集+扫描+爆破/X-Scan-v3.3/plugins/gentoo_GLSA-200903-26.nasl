# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-26.xml
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
 script_id(35916);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-26");
 script_cve_id("CVE-2008-2828");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-26
(TMSNC: Execution of arbitrary code)


    Nico Golde reported a stack-based buffer overflow when processing a MSN
    packet with a UBX command containing a large UBX payload length field.
  
Impact

    A remote attacker could send a specially crafted message, possibly
    resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Since TMSNC is no longer maintained, we recommend that users unmerge
    the vulnerable package and switch to another console-based MSN client
    such as CenterIM or Pebrot:
    # emerge --unmerge "net-im/tmsnc"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2828');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-26] TMSNC: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TMSNC: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/tmsnc", unaffected: make_list(), vulnerable: make_list("le 0.3.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

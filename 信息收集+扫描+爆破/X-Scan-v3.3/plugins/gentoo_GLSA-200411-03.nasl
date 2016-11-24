# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-03.xml
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
 script_id(15606);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-03");
 script_cve_id("CVE-2004-0940");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-03
(Apache 1.3: Buffer overflow vulnerability in mod_include)


    A possible buffer overflow exists in the get_tag() function of
    mod_include.c.
  
Impact

    If Server Side Includes (SSI) are enabled, a local attacker may be able to
    run arbitrary code with the rights of an httpd child process by making use
    of a specially-crafted document with malformed SSI.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-1.3.32-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0940');
script_set_attribute(attribute: 'see_also', value: 'http://www.apacheweek.com/features/security-13');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-03] Apache 1.3: Buffer overflow vulnerability in mod_include');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Buffer overflow vulnerability in mod_include');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 1.3.32-r1"), vulnerable: make_list("lt 1.3.32-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
